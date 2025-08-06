import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import HTTPException

from src.core.service.auth.cache.session_store import SessionStore
from src.core.service.auth.models.session import UserSession, DeviceInfo, SessionStatus
from src.core.service.auth.session_service import UserSessionService
from src.infra.config.redis import get_redis
from src.infra.config.settings import get_settings

settings = get_settings()

TEST_WALLET_ADDRESS = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
TEST_DEVICE_INFO = DeviceInfo(
    user_agent="Test Browser 1.0",
    ip_address="127.0.0.1",
    device_id="test-device-1"
)
TEST_DEVICE_INFO_2 = DeviceInfo(
    user_agent="Test Browser 2.0",
    ip_address="127.0.0.2",
    device_id="test-device-2"
)


@pytest.fixture
async def redis_client():
    client = await get_redis()
    try:
        yield client
    finally:
        await client.close()


@pytest.fixture
async def session_store(redis_client):
    async for client in redis_client:
        store = SessionStore(client)
        try:
            yield store
        finally:
            # Cleanup if needed
            pass


@pytest.fixture
async def session_service(session_store):
    async for store in session_store:
        service = UserSessionService(store)
        try:
            yield service
        finally:
            # Cleanup if needed
            pass


@pytest.mark.asyncio
async def test_create_first_session(session_service):
    """Should create first session for new user"""
    async for service in session_service:
        session = await service.create_session(
            TEST_WALLET_ADDRESS,
            TEST_DEVICE_INFO
        )

        assert isinstance(session.id, UUID)
        assert session.wallet_address == TEST_WALLET_ADDRESS
        assert session.device_info == TEST_DEVICE_INFO
        assert session.status == SessionStatus.ACTIVE
        assert isinstance(session.created_at, datetime)
        assert isinstance(session.last_active_at, datetime)
        assert session.invalidated_at is None
        assert session.invalidation_reason is None


@pytest.mark.asyncio
async def test_create_session_invalidates_old_device_session(session_service):
    """Should invalidate old session from same device"""
    async for service in session_service:
        # Create first session
        first_session = await service.create_session(
            TEST_WALLET_ADDRESS,
            TEST_DEVICE_INFO
        )

        # Create second session from same device
        second_session = await service.create_session(
            TEST_WALLET_ADDRESS,
            TEST_DEVICE_INFO
        )

        # Get updated first session
        old_session = await service.get_session(first_session.id)

        assert old_session.status == SessionStatus.INVALIDATED
        assert old_session.invalidation_reason == "New login from same device"
        assert second_session.status == SessionStatus.ACTIVE


@pytest.mark.asyncio
async def test_multiple_device_sessions(session_service):
    """Should allow multiple active sessions from different devices"""
    async for service in session_service:
        # Create sessions from different devices
        session1 = await service.create_session(
            TEST_WALLET_ADDRESS,
            TEST_DEVICE_INFO
        )
        session2 = await service.create_session(
            TEST_WALLET_ADDRESS,
            TEST_DEVICE_INFO_2
        )

        # Both sessions should be active
        assert session1.status == SessionStatus.ACTIVE
        assert session2.status == SessionStatus.ACTIVE

        # Get user sessions
        sessions = await service.get_user_sessions(TEST_WALLET_ADDRESS)
        active_sessions = [s for s in sessions if s.is_active]
        assert len(active_sessions) == 2


@pytest.mark.asyncio
async def test_session_activity_tracking(session_service):
    """Should update last activity timestamp"""
    async for service in session_service:
        # Create session
        session = await service.create_session(
            TEST_WALLET_ADDRESS,
            TEST_DEVICE_INFO
        )
        created_at = session.last_active_at

        # Wait a moment
        await asyncio.sleep(0.1)

        # Update activity
        updated = await service.update_session_activity(session.id)
        assert updated.last_active_at > created_at


@pytest.mark.asyncio
async def test_session_timeout(session_service):
    """Should timeout inactive sessions"""
    async for service in session_service:
        # Create session with short timeout
        service.session_inactivity_minutes = 0

        session = await service.create_session(
            TEST_WALLET_ADDRESS,
            TEST_DEVICE_INFO
        )

        # Wait a moment
        await asyncio.sleep(0.1)

        # Try to update activity
        with pytest.raises(HTTPException) as exc_info:
            await service.update_session_activity(session.id)

            assert exc_info.value.status_code == 401
            assert "timed out" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_invalidate_all_user_sessions(session_service):
    """Should invalidate all user sessions except excluded"""
    async for service in session_service:
        # Create multiple sessions
        session1 = await service.create_session(
            TEST_WALLET_ADDRESS,
            TEST_DEVICE_INFO
        )
        session2 = await service.create_session(
            TEST_WALLET_ADDRESS,
            TEST_DEVICE_INFO_2
        )

        # Invalidate all sessions except session1
        await service.invalidate_user_sessions(
            TEST_WALLET_ADDRESS,
            "Security check",
            exclude_session_id=session1.id
        )

        # Check sessions status
        updated1 = await service.get_session(session1.id)
        updated2 = await service.get_session(session2.id)

        assert updated1.status == SessionStatus.ACTIVE
        assert updated2.status == SessionStatus.INVALIDATED
        assert updated2.invalidation_reason == "Security check"


@pytest.mark.asyncio
async def test_get_nonexistent_session(session_service):
    """Should handle nonexistent session gracefully"""
    async for service in session_service:
        with pytest.raises(HTTPException) as exc_info:
            await service.get_session(UUID("00000000-0000-0000-0000-000000000000"))

        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_update_inactive_session(session_service):
    """Should reject activity update for inactive session"""
    async for service in session_service:
        # Create and invalidate session
        session = await service.create_session(
            TEST_WALLET_ADDRESS,
            TEST_DEVICE_INFO
        )
        await service.invalidate_session(session.id, "Test invalidation")

        # Try to update activity
        with pytest.raises(HTTPException) as exc_info:
            await service.update_session_activity(session.id)

        assert exc_info.value.status_code == 401
        assert "not active" in exc_info.value.detail.lower()
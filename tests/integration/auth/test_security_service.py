import asyncio
import pytest
from datetime import datetime, timezone
from uuid import UUID, uuid4

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import HTTPException

from src.core.service.auth.cache.audit_store import AuthAuditStore
from src.core.service.auth.models.audit import AuthEventType, AuthEventStatus
from src.core.service.auth.models.session import DeviceInfo
from src.core.service.auth.security_service import SecurityService
from src.core.service.auth.multi_protocol_signature_service import MultiProtocolSignatureService
from src.core.service.auth.protocols.base import BlockchainProtocol, protocol_registry
from src.core.service.auth.protocols.evm import create_evm_verifier
from src.infra.config.redis import get_redis
from src.infra.config.settings import get_settings

settings = get_settings()

# Test data
TEST_DEVICE_INFO = DeviceInfo(
    user_agent="Test Browser 1.0",
    ip_address="127.0.0.1",
    device_id="test-device-1"
)


def create_test_wallet():
    """Create a new test wallet for each test"""
    account = Account.create()
    return account.address, account.key


@pytest.fixture
async def redis_client():
    client = await get_redis()
    try:
        yield client
    finally:
        await client.close()


@pytest.fixture
async def audit_store(redis_client):
    async for client in redis_client:
        store = AuthAuditStore(client)
        try:
            yield store
        finally:
            # Cleanup if needed
            pass


@pytest.fixture
async def signature_service():
    # Register EVM verifier for tests
    evm_verifier = create_evm_verifier("mainnet", chain_id=1)
    await evm_verifier.initialize()
    protocol_registry.register(evm_verifier)
    return MultiProtocolSignatureService()


@pytest.fixture
async def security_service(audit_store, signature_service):
    async for store in audit_store:
        sig_service = await signature_service
        service = SecurityService(store, sig_service)
        try:
            yield service
        finally:
            # Cleanup if needed
            pass


def sign_message(message: str, private_key: bytes) -> str:
    """Helper to sign a message with test wallet"""
    # Create standard Ethereum message format
    encoded = encode_defunct(text=message)
    signed = Account.sign_message(encoded, private_key)
    return signed.signature.hex()


@pytest.mark.asyncio
async def test_generate_secure_secret(security_service):
    """Should generate secure random secret"""
    async for service in security_service:
        secret1 = service.generate_secure_secret()
        secret2 = service.generate_secure_secret()

        assert len(secret1) > 32  # At least 256 bits
        assert secret1 != secret2  # Should be random


@pytest.mark.asyncio
async def test_verify_sensitive_operation_success(security_service):
    """Should verify signature for sensitive operation"""
    async for service in security_service:
        # Create test wallet and message
        wallet_address, private_key = create_test_wallet()
        message = "I authorize this sensitive operation"
        signature = sign_message(message, private_key)

        # Verify operation
        result = await service.verify_sensitive_operation(
            wallet_address,
            signature,
            message,
            TEST_DEVICE_INFO,
            "transfer",
            BlockchainProtocol.EVM,
            uuid4()
        )

        assert result is True

        # Check audit log
        logs = await service.audit_store.get_user_logs(wallet_address)
        assert len(logs) == 1
        assert logs[0].event_type == AuthEventType.SENSITIVE_OPERATION
        assert logs[0].status == AuthEventStatus.SUCCESS


@pytest.mark.asyncio
async def test_verify_sensitive_operation_failure(security_service):
    """Should handle invalid signature"""
    async for service in security_service:
        # Create test wallet and messages
        wallet_address, private_key = create_test_wallet()
        message = "I authorize this sensitive operation"
        wrong_message = "I authorize a different operation"
        signature = sign_message(message, private_key)

        # Verify operation with wrong message
        result = await service.verify_sensitive_operation(
            wallet_address,
            signature,
            wrong_message,
            TEST_DEVICE_INFO,
            "transfer",
            BlockchainProtocol.EVM,
            uuid4()
        )

        assert result is False

        # Check audit log
        logs = await service.audit_store.get_user_logs(wallet_address)
        assert len(logs) == 1
        assert logs[0].event_type == AuthEventType.SENSITIVE_OPERATION
        assert logs[0].status == AuthEventStatus.FAILURE


@pytest.mark.asyncio
async def test_account_lockout(security_service):
    """Should lock account after max failed attempts"""
    async for service in security_service:
        # Create test wallet and messages
        wallet_address, private_key = create_test_wallet()
        message = "I authorize this sensitive operation"
        wrong_message = "I authorize a different operation"
        signature = sign_message(message, private_key)

        # Make multiple failed attempts
        for _ in range(settings.MAX_FAILED_AUTH_ATTEMPTS):
            result = await service.verify_sensitive_operation(
                wallet_address,
                signature,
                wrong_message,
                TEST_DEVICE_INFO,
                "transfer",
                BlockchainProtocol.EVM,
                uuid4()
            )
            assert result is False

        # Next attempt should be blocked
        with pytest.raises(HTTPException) as exc_info:
            await service.verify_sensitive_operation(
                wallet_address,
                signature,
                message,
                TEST_DEVICE_INFO,
                "transfer",
                BlockchainProtocol.EVM,
                uuid4()
            )

        assert exc_info.value.status_code == 403
        assert "locked" in exc_info.value.detail.lower()

        # Check audit logs
        logs = await service.audit_store.get_user_logs(wallet_address)
        assert len(logs) == settings.MAX_FAILED_AUTH_ATTEMPTS + 2  # +1 for lockout, +1 for blocked attempt

        # Verify lockout log
        lockout_log = next(
            log for log in logs
            if log.event_type == AuthEventType.ACCOUNT_LOCKED
        )
        assert lockout_log.status == AuthEventStatus.BLOCKED

        # Verify blocked attempt log
        blocked_log = next(
            log for log in logs
            if log.status == AuthEventStatus.BLOCKED
        )
        assert blocked_log.event_type == AuthEventType.SENSITIVE_OPERATION


@pytest.mark.asyncio
async def test_reset_failed_attempts(security_service):
    """Should reset failed attempts after successful verification"""
    async for service in security_service:
        # Create test wallet and messages
        wallet_address, private_key = create_test_wallet()
        message = "I authorize this sensitive operation"
        wrong_message = "I authorize a different operation"
        signature = sign_message(message, private_key)

        # Make some failed attempts
        for _ in range(settings.MAX_FAILED_AUTH_ATTEMPTS - 1):
            result = await service.verify_sensitive_operation(
                wallet_address,
                signature,
                wrong_message,
                TEST_DEVICE_INFO,
                "transfer",
                BlockchainProtocol.EVM,
                uuid4()
            )
            assert result is False

        # Successful attempt should reset counter
        result = await service.verify_sensitive_operation(
            wallet_address,
            signature,
            message,
            TEST_DEVICE_INFO,
            "transfer",
            BlockchainProtocol.EVM,
            uuid4()
        )
        assert result is True

        # Check audit logs
        logs = await service.audit_store.get_user_logs(wallet_address)
        
        # Should have failed attempts + success
        assert len(logs) == (settings.MAX_FAILED_AUTH_ATTEMPTS - 1) + 1

        # Verify success log
        success_log = next(
            log for log in logs
            if log.status == AuthEventStatus.SUCCESS
        )
        assert success_log.event_type == AuthEventType.SENSITIVE_OPERATION


@pytest.mark.asyncio
async def test_audit_log_retention(security_service):
    """Should expire audit logs after retention period"""
    async for service in security_service:
        # Create test wallet and message
        wallet_address, private_key = create_test_wallet()
        message = "I authorize this sensitive operation"
        signature = sign_message(message, private_key)

        # Override retention for test
        service.audit_store.audit_retention_days = 0

        # Create some audit logs
        await service.verify_sensitive_operation(
            wallet_address,
            signature,
            message,
            TEST_DEVICE_INFO,
            "transfer",
            BlockchainProtocol.EVM,
            uuid4()
        )

        # Wait for expiry
        await asyncio.sleep(1)

        # Logs should be expired
        logs = await service.audit_store.get_user_logs(wallet_address)
        assert len(logs) == 0
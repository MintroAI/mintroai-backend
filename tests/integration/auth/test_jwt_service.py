import asyncio
import jwt
import pytest
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from typing import AsyncGenerator

from src.core.service.auth.jwt_service import JWTService
from src.core.service.auth.models.token import TokenType
from src.infra.config.redis import get_redis
from src.infra.config.settings import get_settings

settings = get_settings()

TEST_WALLET_ADDRESS = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"


@pytest.fixture
async def redis_client() -> AsyncGenerator:
    client = await get_redis()
    try:
        yield client
    finally:
        await client.close()


@pytest.fixture
async def jwt_service(redis_client):
    async for client in redis_client:
        service = JWTService(client)
        try:
            yield service
        finally:
            # Cleanup if needed
            pass


@pytest.mark.asyncio
async def test_create_tokens(jwt_service):
    """Should create valid access and refresh tokens"""
    async for service in jwt_service:
        tokens = await service.create_tokens(TEST_WALLET_ADDRESS)

        assert tokens.access_token
        assert tokens.refresh_token
        assert tokens.token_type == "bearer"
        assert tokens.expires_in > 0

        # Verify both tokens
        access_payload = await service.verify_token(
            tokens.access_token,
            TokenType.ACCESS
        )
        refresh_payload = await service.verify_token(
            tokens.refresh_token,
            TokenType.REFRESH
        )

        # Check payload contents
        assert access_payload.wallet_address == TEST_WALLET_ADDRESS
        assert refresh_payload.wallet_address == TEST_WALLET_ADDRESS
        assert access_payload.type == TokenType.ACCESS
        assert refresh_payload.type == TokenType.REFRESH


@pytest.mark.asyncio
async def test_verify_token_with_wrong_type(jwt_service):
    """Should reject token when used with wrong type"""
    async for service in jwt_service:
        tokens = await service.create_tokens(TEST_WALLET_ADDRESS)

        with pytest.raises(HTTPException) as exc_info:
            await service.verify_token(tokens.access_token, TokenType.REFRESH)

        assert exc_info.value.status_code == 401
        assert "Invalid token type" in exc_info.value.detail


@pytest.mark.asyncio
async def test_verify_expired_token(jwt_service):
    """Should reject expired tokens"""
    async for service in jwt_service:
        # Create token with minimal expiry
        token, _ = service._create_token(
            TEST_WALLET_ADDRESS,
            TokenType.ACCESS,
            expires_delta=timedelta(microseconds=1)
        )

        # Wait for token to expire
        await asyncio.sleep(0.1)

        with pytest.raises(HTTPException) as exc_info:
            await service.verify_token(token, TokenType.ACCESS)

        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_refresh_token_flow(jwt_service):
    """Should issue new token pair and blacklist old refresh token"""
    async for service in jwt_service:
        # Get initial tokens
        initial_tokens = await service.create_tokens(TEST_WALLET_ADDRESS)

        # Use refresh token to get new tokens
        new_tokens = await service.refresh_access_token(initial_tokens.refresh_token)

        assert new_tokens.access_token != initial_tokens.access_token
        assert new_tokens.refresh_token != initial_tokens.refresh_token

        # Old refresh token should be blacklisted
        with pytest.raises(HTTPException) as exc_info:
            await service.verify_token(
                initial_tokens.refresh_token,
                TokenType.REFRESH
            )

        assert exc_info.value.status_code == 401
        assert "revoked" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_revoke_token(jwt_service):
    """Should successfully blacklist a token"""
    async for service in jwt_service:
        tokens = await service.create_tokens(TEST_WALLET_ADDRESS)

        # Revoke access token
        await service.revoke_token(
            tokens.access_token,
            reason="Test revocation"
        )

        # Verify token is blacklisted
        with pytest.raises(HTTPException) as exc_info:
            await service.verify_token(tokens.access_token, TokenType.ACCESS)

        assert exc_info.value.status_code == 401
        assert "revoked" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_blacklist_expired_token(jwt_service):
    """Should handle blacklisting of already expired tokens"""
    async for service in jwt_service:
        # Create expired token
        token, _ = service._create_token(
            TEST_WALLET_ADDRESS,
            TokenType.ACCESS,
            expires_delta=timedelta(microseconds=1)
        )

        # Wait for token to expire
        await asyncio.sleep(0.1)

        # Should not raise exception for expired token
        await service.revoke_token(token, reason="Expired token test")


@pytest.mark.asyncio
async def test_token_blacklist_cleanup(jwt_service, redis_client):
    """Should automatically clean up expired blacklist entries"""
    async for service in jwt_service:
        async for client in redis_client:
            # Create token with short expiry
            token, exp = service._create_token(
                TEST_WALLET_ADDRESS,
                TokenType.ACCESS,
                expires_delta=timedelta(seconds=1)
            )

            # Blacklist the token
            await service.revoke_token(token)

            # Verify it's blacklisted
            with pytest.raises(HTTPException):
                await service.verify_token(token, TokenType.ACCESS)

            # Wait for token and blacklist entry to expire
            await asyncio.sleep(
                1 + settings.TOKEN_BLACKLIST_EXPIRE_MARGIN_MINUTES * 60
            )

            # Check that blacklist entry was cleaned up
            payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            key = f"blacklist:token:{payload['jti']}"
            assert not await client.exists(key)
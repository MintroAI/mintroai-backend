import pytest
import asyncio
from datetime import datetime, timedelta

from src.core.service.auth.models.challenge import Challenge, ChallengeStatus
from src.core.service.auth.challenge_service import ChallengeService
from src.core.service.auth.cache.challenge_store import ChallengeStore
from src.infra.config.redis import get_redis


@pytest.mark.asyncio
async def test_create_challenge():
    """Test challenge creation with valid wallet address"""
    # Setup
    redis_client = await get_redis()
    await redis_client.flushdb()
    
    try:
        store = ChallengeStore(redis_client)
        service = ChallengeService(store)
        wallet_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        
        # Test
        challenge = await service.create_challenge(wallet_address)
        
        # Assert
        assert challenge.wallet_address == wallet_address.lower()
        assert challenge.nonce.startswith("0x")
        assert len(challenge.nonce) == 66  # 0x + 64 hex chars
        assert challenge.status == ChallengeStatus.PENDING
        assert challenge.message.startswith("Sign in to MintroAI")
        assert challenge.nonce in challenge.message
        
    finally:
        await redis_client.flushdb()
        await redis_client.close()
        await redis_client.connection_pool.disconnect()


@pytest.mark.asyncio
async def test_challenge_expiry():
    """Test challenge expiry handling"""
    # Setup
    redis_client = await get_redis()
    await redis_client.flushdb()
    
    try:
        store = ChallengeStore(redis_client)
        service = ChallengeService(store)
        wallet_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        
        # Create challenge and wait for expiry logic
        challenge = await service.create_challenge(wallet_address)
        
        # Manually expire the challenge by setting past expiry time
        challenge.expires_at = datetime.utcnow() - timedelta(minutes=1)
        
        # Force save the expired challenge by bypassing TTL check
        await redis_client.setex(
            f"auth:challenge:{wallet_address.lower()}",
            1,  # 1 second TTL
            store._serialize_challenge(challenge)
        )
        
        # Try to get expired challenge - should return None due to expiry check
        active_challenge = await service.get_active_challenge(wallet_address)
        assert active_challenge is None
        
    finally:
        await redis_client.flushdb()
        await redis_client.close()
        await redis_client.connection_pool.disconnect()


@pytest.mark.asyncio
async def test_duplicate_challenge():
    """Test handling of duplicate challenge requests"""
    # Setup
    redis_client = await get_redis()
    await redis_client.flushdb()
    
    try:
        store = ChallengeStore(redis_client)
        service = ChallengeService(store)
        wallet_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        
        # Create first challenge
        challenge1 = await service.create_challenge(wallet_address)
        
        # Request another challenge
        challenge2 = await service.create_challenge(wallet_address)
        
        # Should return the same challenge
        assert challenge1.nonce == challenge2.nonce
        assert challenge1.wallet_address == challenge2.wallet_address
        
    finally:
        await redis_client.flushdb()
        await redis_client.close()
        await redis_client.connection_pool.disconnect()


@pytest.mark.asyncio
async def test_invalid_wallet_address():
    """Test challenge creation with invalid wallet address"""
    # Setup
    redis_client = await get_redis()
    await redis_client.flushdb()
    
    try:
        store = ChallengeStore(redis_client)
        service = ChallengeService(store)
        invalid_addresses = [
            "invalid",
            "0x123",  # too short
            "0x" + "1" * 39,  # too short (41 chars total)
            "1234567890" * 4,  # no 0x prefix
            "0x" + "g" * 40,  # invalid hex characters
        ]
        
        for address in invalid_addresses:
            with pytest.raises(ValueError, match="Invalid wallet address format"):
                await service.create_challenge(address)
                
    finally:
        await redis_client.flushdb()
        await redis_client.close()
        await redis_client.connection_pool.disconnect()


@pytest.mark.asyncio
async def test_challenge_invalidation():
    """Test challenge invalidation"""
    # Setup
    redis_client = await get_redis()
    await redis_client.flushdb()
    
    try:
        store = ChallengeStore(redis_client)
        service = ChallengeService(store)
        wallet_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        
        # Create challenge
        challenge = await service.create_challenge(wallet_address)
        assert challenge.status == ChallengeStatus.PENDING
        
        # Invalidate challenge
        await service.invalidate_challenge(wallet_address, ChallengeStatus.USED)
        
        # Check challenge is invalidated
        active_challenge = await service.get_active_challenge(wallet_address)
        assert active_challenge is None
        
    finally:
        await redis_client.flushdb()
        await redis_client.close()
        await redis_client.connection_pool.disconnect()
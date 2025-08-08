import pytest
from datetime import datetime, timedelta, timezone
import os
import sys

# Add the project root to the sys.path to allow importing modules from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from eth_account import Account
from eth_account.messages import encode_defunct

from src.core.service.auth.models.challenge import Challenge, ChallengeStatus
from src.core.service.auth.challenge_service import ChallengeService
from src.core.service.auth.cache.challenge_store import ChallengeStore
from src.core.service.auth.multi_protocol_signature_service import MultiProtocolSignatureService
from src.core.service.auth.protocols.base import protocol_registry
from src.core.service.auth.protocols.evm import create_evm_verifier
from src.infra.config.redis import get_redis


@pytest.fixture
def test_wallet():
    """Create a test wallet for signature verification"""
    # Create a new random account for testing
    account = Account.create()
    return {
        'address': account.address,
        'key': account.key
    }


async def setup_challenge_service():
    """Helper function to setup challenge service with EVM verifier"""
    # Initialize EVM verifier for tests
    evm_verifier = create_evm_verifier("mainnet", chain_id=1)
    await evm_verifier.initialize()
    protocol_registry.register(evm_verifier)
    
    redis_client = await get_redis()
    await redis_client.flushdb()
    
    store = ChallengeStore(redis_client)
    multi_signature_service = MultiProtocolSignatureService()
    challenge_service = ChallengeService(store, multi_signature_service)
    
    return challenge_service, redis_client


@pytest.mark.asyncio
async def test_create_challenge():
    """Test challenge creation with valid wallet address"""
    challenge_service, redis_client = await setup_challenge_service()
    
    try:
        
        wallet_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        
        challenge = await challenge_service.create_challenge(wallet_address)
        
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
    challenge_service, redis_client = await setup_challenge_service()
    
    try:
        
        wallet_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        
        # Create challenge and wait for expiry logic
        challenge = await challenge_service.create_challenge(wallet_address)
        
        # Manually expire the challenge by setting past expiry time
        challenge.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        # Force save the expired challenge by bypassing TTL check in ChallengeStore.save_challenge
        # We set a very short TTL (e.g., 1 second) to ensure it's saved but immediately expires for get_active_challenge
        await challenge_service.store.redis.setex(
            f"auth:challenge:{wallet_address.lower()}",
            1,  # 1 second TTL
            challenge_service.store._serialize_challenge(challenge)
        )
        
        # Try to get expired challenge - should return None due to expiry check
        active_challenge = await challenge_service.get_active_challenge(wallet_address)
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
        multi_signature_service = MultiProtocolSignatureService()
        challenge_service = ChallengeService(store, multi_signature_service)
        
        wallet_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        
        # Create first challenge
        challenge1 = await challenge_service.create_challenge(wallet_address)
        
        # Request another challenge
        challenge2 = await challenge_service.create_challenge(wallet_address)
        
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
        multi_signature_service = MultiProtocolSignatureService()
        challenge_service = ChallengeService(store, multi_signature_service)
        
        invalid_addresses = [
            "invalid",
            "0x123",  # too short
            "0x" + "1" * 39,  # too short (41 chars total)
            "1234567890" * 4,  # no 0x prefix
            "0x" + "g" * 40,  # invalid hex characters
        ]
        
        for address in invalid_addresses:
            with pytest.raises(ValueError, match="Invalid evm address"):
                await challenge_service.create_challenge(address)
                
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
        multi_signature_service = MultiProtocolSignatureService()
        challenge_service = ChallengeService(store, multi_signature_service)
        
        wallet_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        
        # Create challenge
        challenge = await challenge_service.create_challenge(wallet_address)
        assert challenge.status == ChallengeStatus.PENDING
        
        # Invalidate challenge
        await challenge_service.invalidate_challenge(wallet_address, ChallengeStatus.USED)
        
        # Check challenge is invalidated
        active_challenge = await challenge_service.get_active_challenge(wallet_address)
        assert active_challenge is None
        
    finally:
        await redis_client.flushdb()
        await redis_client.close()
        await redis_client.connection_pool.disconnect()


@pytest.mark.asyncio
async def test_verify_challenge_success(test_wallet):
    """Test successful challenge verification"""
    # Setup
    redis_client = await get_redis()
    await redis_client.flushdb()
    
    try:
        store = ChallengeStore(redis_client)
        multi_signature_service = MultiProtocolSignatureService()
        challenge_service = ChallengeService(store, multi_signature_service)
        
        # Create challenge
        challenge = await challenge_service.create_challenge(test_wallet['address'])
        
        # Sign the challenge message
        signable_message = encode_defunct(text=challenge.message)
        signed_message = Account.sign_message(signable_message, private_key=test_wallet['key'])
        
        # Verify the signature
        is_valid, error = await challenge_service.verify_challenge(
            wallet_address=test_wallet['address'],
            signature=signed_message.signature
        )
        
        assert is_valid is True
        assert error is None
        
        # Check challenge status
        challenge = await challenge_service.store.get_challenge(test_wallet['address'])
        assert challenge.status == ChallengeStatus.VERIFIED
        
    finally:
        await redis_client.flushdb()
        await redis_client.close()
        await redis_client.connection_pool.disconnect()


@pytest.mark.asyncio
async def test_verify_challenge_wrong_signature(test_wallet):
    """Test challenge verification with wrong signature"""
    # Setup
    redis_client = await get_redis()
    await redis_client.flushdb()
    
    try:
        store = ChallengeStore(redis_client)
        multi_signature_service = MultiProtocolSignatureService()
        challenge_service = ChallengeService(store, multi_signature_service)
        
        # Create challenge
        challenge = await challenge_service.create_challenge(test_wallet['address'])
        
        # Sign a different message
        different_message = "Different message"
        signable_message = encode_defunct(text=different_message)
        signed_message = Account.sign_message(signable_message, private_key=test_wallet['key'])
        
        # Verify the signature
        is_valid, error = await challenge_service.verify_challenge(
            wallet_address=test_wallet['address'],
            signature=signed_message.signature
        )
        
        assert is_valid is False
        assert "Recovered address does not match claimed address" in error
        
        # Check challenge status
        challenge = await challenge_service.store.get_challenge(test_wallet['address'])
        assert challenge.status == ChallengeStatus.INVALID
        
    finally:
        await redis_client.flushdb()
        await redis_client.close()
        await redis_client.connection_pool.disconnect()


@pytest.mark.asyncio
async def test_verify_challenge_no_active_challenge(test_wallet):
    """Test challenge verification without an active challenge"""
    # Setup
    redis_client = await get_redis()
    await redis_client.flushdb()
    
    try:
        store = ChallengeStore(redis_client)
        multi_signature_service = MultiProtocolSignatureService()
        challenge_service = ChallengeService(store, multi_signature_service)
        
        # Try to verify without creating a challenge
        is_valid, error = await challenge_service.verify_challenge(
            wallet_address=test_wallet['address'],
            signature="0x1234567890"
        )
        
        assert is_valid is False
        assert "No active challenge found" in error
        
    finally:
        await redis_client.flushdb()
        await redis_client.close()
        await redis_client.connection_pool.disconnect()


@pytest.mark.asyncio
async def test_verify_challenge_invalid_signature_format(test_wallet):
    """Test challenge verification with invalid signature format"""
    # Setup
    redis_client = await get_redis()
    await redis_client.flushdb()
    
    try:
        store = ChallengeStore(redis_client)
        multi_signature_service = MultiProtocolSignatureService()
        challenge_service = ChallengeService(store, multi_signature_service)
        
        # Create challenge
        await challenge_service.create_challenge(test_wallet['address'])
        
        invalid_signatures = [
            "invalid",
            "0x123",  # too short
            "not-hex-0x1234",
            "0x" + "g" * 130,  # invalid hex characters
        ]
        
        for signature in invalid_signatures:
            # Create a new challenge for each invalid signature test
            await challenge_service.create_challenge(test_wallet['address'])
            
            is_valid, error = await challenge_service.verify_challenge(
                wallet_address=test_wallet['address'],
                signature=signature
            )
            
            assert is_valid is False
            assert ("Invalid signature format" in error or "EVM signature verification error" in error)
            
            # Check challenge status
            challenge = await challenge_service.store.get_challenge(test_wallet['address'])
            assert challenge.status == ChallengeStatus.INVALID
            
    finally:
        await redis_client.flushdb()
        await redis_client.close()
        await redis_client.connection_pool.disconnect()
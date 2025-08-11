"""
Integration tests for complete NEAR authentication flow.
Tests the full end-to-end authentication process for NEAR protocol.
"""

import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

# Add the project root to the sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.core.service.auth.challenge_service import ChallengeService
from src.core.service.auth.security_service import SecurityService
from src.core.service.auth.jwt_service import JWTService
from src.core.service.auth.multi_protocol_signature_service import MultiProtocolSignatureService
from src.core.service.auth.cache.challenge_store import ChallengeStore
from src.core.service.auth.cache.audit_store import AuthAuditStore
from src.core.service.auth.protocols.base import BlockchainProtocol
from src.core.service.auth.protocols.near import NEARVerifier, NEARConfig
from src.core.service.auth.models.session import DeviceInfo
from src.core.service.auth.utils.crypto import (
    generate_ed25519_keypair,
    sign_message_ed25519,
    format_near_public_key
)
from src.infra.config.redis import get_redis


class TestNEARFullAuthenticationFlow:
    """Test complete NEAR authentication flow from challenge to protected operations"""
    
    @pytest.fixture
    async def redis_client(self):
        """Create Redis client for testing"""
        client = await get_redis()
        await client.flushdb()  # Clean state
        return client
    
    @pytest.fixture
    def near_test_accounts(self):
        """Create multiple test NEAR accounts"""
        accounts = []
        for i in range(3):
            private_key, public_key = generate_ed25519_keypair()
            accounts.append({
                'account_id': f'test-account-{i}.testnet',
                'private_key': private_key,
                'public_key': public_key,
                'near_public_key': format_near_public_key(public_key)
            })
        return accounts
    
    @pytest.fixture
    def implicit_account(self):
        """Create implicit NEAR account"""
        private_key, public_key = generate_ed25519_keypair()
        import hashlib
        implicit_id = hashlib.sha256(str(public_key).encode()).hexdigest()
        
        return {
            'account_id': implicit_id,
            'private_key': private_key,
            'public_key': public_key,
            'near_public_key': format_near_public_key(public_key)
        }
    
    @pytest.fixture
    def device_info(self):
        """Create test device info"""
        return DeviceInfo(
            ip_address="192.168.1.100",
            user_agent="Test Agent/1.0",
            device_id="test_device_123"
        )
    
    async def setup_auth_services(self):
        """Helper function to setup auth services with protocol verifiers"""
        from src.core.service.auth.protocols.near import NEARVerifier, NEARConfig
        from src.core.service.auth.protocols.evm import EVMVerifier, EVMConfig
        from src.core.service.auth.protocols.base import protocol_registry, BlockchainProtocol
        
        # Register protocol verifiers
        evm_config = EVMConfig(protocol=BlockchainProtocol.EVM, network_id="mainnet", chain_id=1)
        near_config = NEARConfig(
            protocol=BlockchainProtocol.NEAR,
            network_id="testnet",
            rpc_urls=["https://rpc.testnet.near.org"],
            enabled=True,
            max_retries=3,
            timeout_seconds=30
        )
        
        evm_verifier = EVMVerifier(evm_config)
        near_verifier = NEARVerifier(near_config)
        
        protocol_registry.register(evm_verifier)
        protocol_registry.register(near_verifier)
        
        redis_client = await get_redis()
        await redis_client.flushdb()
        
        challenge_store = ChallengeStore(redis_client)
        audit_store = AuthAuditStore(redis_client)
        multi_signature_service = MultiProtocolSignatureService()
        
        challenge_service = ChallengeService(challenge_store, multi_signature_service)
        security_service = SecurityService(audit_store, multi_signature_service)
        jwt_service = JWTService(redis_client)
        
        services = {
            'challenge': challenge_service,
            'security': security_service,
            'jwt': jwt_service,
            'multi_sig': multi_signature_service
        }
        
        return services, redis_client

    @pytest.mark.asyncio
    async def test_complete_near_authentication_flow(self, near_test_accounts, device_info):
        """Test complete NEAR authentication flow: challenge -> verify -> tokens -> protected operation"""
        account = near_test_accounts[0]
        services, redis_client = await self.setup_auth_services()
        
        try:
            # Step 1: Create challenge
            challenge = await services['challenge'].create_challenge(
            wallet_address=account['account_id'],
            protocol=BlockchainProtocol.NEAR
            )
            
            assert challenge is not None
            assert challenge.protocol == "near"
            assert challenge.wallet_address == account['account_id']
            assert "Sign in to MintroAI" in challenge.message
            assert "Network: testnet" in challenge.message
            
            # Step 2: Sign the challenge message
            signature = sign_message_ed25519(challenge.message, account['private_key'])
            
            # Step 3: Verify the challenge
            is_valid, error = await services['challenge'].verify_challenge(
            wallet_address=account['account_id'],
            signature=signature,
            protocol=BlockchainProtocol.NEAR,
            public_key=account['near_public_key']
            )
            
            assert is_valid is True
            assert error is None
            
            # Step 4: Generate JWT tokens
            tokens = await services['jwt'].create_tokens(account['account_id'])
            access_token = tokens.access_token
            refresh_token = tokens.refresh_token
            
            assert access_token is not None
            assert refresh_token is not None
            
            # Step 5: Verify access token
            from src.core.service.auth.models.token import TokenType
            payload = await services['jwt'].verify_token(access_token, TokenType.ACCESS)
            assert payload.wallet_address == account['account_id']
            
            # Step 6: Use token for protected operation (sensitive operation verification)
            operation_message = f"Transfer 100 NEAR from {account['account_id']} to recipient.testnet"
            operation_signature = sign_message_ed25519(operation_message, account['private_key'])
            
            operation_valid = await services['security'].verify_sensitive_operation(
            wallet_address=account['account_id'],
            signature=operation_signature,
            message=operation_message,
            device_info=device_info,
            operation_type="transfer",
            protocol=BlockchainProtocol.NEAR,
            public_key=account['near_public_key']
            )
            
            assert operation_valid is True
            
            # Step 7: Refresh token
            new_tokens = await services['jwt'].refresh_access_token(refresh_token)
            new_access_token = new_tokens.access_token
            assert new_access_token is not None
            assert new_access_token != access_token  # Should be different
            
            # Step 8: Verify new token works
            new_payload = await services['jwt'].verify_token(new_access_token, TokenType.ACCESS)
            assert new_payload.wallet_address == account['account_id']
            
        finally:
            await redis_client.flushdb()
            await redis_client.close()
            await redis_client.connection_pool.disconnect()


"""
Integration tests for NEAR Protocol verifier.
Tests NEAR-specific authentication functionality.
"""

import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Add the project root to the sys.path to allow importing modules from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..')))

from src.core.service.auth.protocols.near import NEARVerifier, NEARConfig, create_near_verifier
from src.core.service.auth.protocols.base import BlockchainProtocol
from src.core.service.auth.utils.crypto import (
    generate_ed25519_keypair,
    sign_message_ed25519,
    format_near_public_key
)


class TestNEARVerifier:
    """Test suite for NEAR protocol verifier"""
    
    @pytest.fixture
    def near_config(self):
        """Create NEAR configuration for testing"""
        return NEARConfig(
            protocol=BlockchainProtocol.NEAR,
            network_id="testnet",
            rpc_urls=[
                "https://rpc.testnet.near.org",
                "https://test.rpc.fastnear.com"
            ],
            enabled=True,
            max_retries=3,
            timeout_seconds=30
        )
    
    @pytest.fixture
    def near_verifier(self, near_config):
        """Create NEAR verifier instance"""
        return NEARVerifier(near_config)
    
    @pytest.fixture
    def test_keypair(self):
        """Generate test keypair for signing tests"""
        private_key, public_key = generate_ed25519_keypair()
        return {
            'private_key': private_key,
            'public_key': public_key,
            'near_public_key': format_near_public_key(public_key)
        }
    
    def test_config_initialization(self, near_config):
        """Test NEAR configuration initialization"""
        assert near_config.protocol == BlockchainProtocol.NEAR
        assert near_config.network_id == "testnet"
        assert len(near_config.rpc_urls) == 2
        assert near_config.enabled is True
        assert near_config.max_retries == 3
    
    def test_verifier_initialization(self, near_verifier):
        """Test NEAR verifier basic initialization"""
        assert near_verifier.protocol == BlockchainProtocol.NEAR
        assert near_verifier.config.network_id == "testnet"
        assert not near_verifier._connection_established
        assert near_verifier.provider is None
    
    @pytest.mark.asyncio
    @patch('src.core.service.auth.protocols.near.Account')
    @patch('src.core.service.auth.protocols.near.JsonProvider')
    async def test_initialize_success(self, mock_provider, mock_account, near_verifier):
        """Test successful NEAR provider initialization"""
        # Mock provider
        mock_provider_instance = MagicMock()
        mock_provider.return_value = mock_provider_instance
        
        # Mock account
        mock_account_instance = AsyncMock()
        mock_account_instance.startup = AsyncMock()
        mock_account_instance.fetch_state = AsyncMock(return_value={"storage_usage": 100})
        mock_account.return_value = mock_account_instance
        
        # Initialize
        await near_verifier.initialize()
        
        # Verify initialization
        assert near_verifier._connection_established
        assert near_verifier.provider is not None
        mock_provider.assert_called_once_with(near_verifier.config.rpc_urls)
        mock_account_instance.startup.assert_called_once()
        mock_account_instance.fetch_state.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('src.core.service.auth.protocols.near.JsonProvider')
    async def test_initialize_failure(self, mock_provider, near_verifier):
        """Test NEAR provider initialization failure"""
        # Mock provider to raise exception
        mock_provider.side_effect = Exception("Connection failed")
        
        # Should raise exception
        with pytest.raises(Exception, match="Connection failed"):
            await near_verifier.initialize()
        
        # Verify state
        assert not near_verifier._connection_established
    
    def test_validate_address_valid_implicit(self, near_verifier):
        """Test validation of valid implicit NEAR account (64 hex chars)"""
        implicit_account = "0123456789abcdef" * 4  # 64 hex chars
        
        is_valid, error = near_verifier.validate_address(implicit_account)
        
        assert is_valid
        assert error is None
    
    def test_validate_address_valid_named(self, near_verifier):
        """Test validation of valid named NEAR accounts"""
        valid_accounts = [
            "alice.testnet",
            "bob.near",
            "test_account",
            "my-app.testnet",
            "sub.parent.testnet",
            "a1",  # minimum length
            "a" * 64,  # maximum length
            "Alice.testnet",  # uppercase (gets normalized to lowercase)
            "TESTACCOUNT.near"  # uppercase (gets normalized to lowercase)
        ]
        
        for account in valid_accounts:
            is_valid, error = near_verifier.validate_address(account)
            assert is_valid, f"Account {account} should be valid, got error: {error}"
            assert error is None
    
    def test_validate_address_invalid_format(self, near_verifier):
        """Test validation of invalid NEAR account formats"""
        invalid_accounts = [
            "",  # empty
            "a",  # too short
            "A" * 65,  # too long
            ".testnet",  # starts with dot
            "testnet.",  # ends with dot
            "test..net",  # consecutive dots
            "-testnet",  # starts with hyphen
            "testnet-",  # ends with hyphen
            "test@net",  # invalid character
            "test net",  # space
            "test/net",  # slash
        ]
        
        for account in invalid_accounts:
            is_valid, error = near_verifier.validate_address(account)
            assert not is_valid, f"Account {account} should be invalid"
            assert error is not None
    
    def test_validate_address_edge_cases(self, near_verifier):
        """Test address validation edge cases"""
        # None input
        is_valid, error = near_verifier.validate_address(None)
        assert not is_valid
        assert "must be a non-empty string" in error
        
        # Non-string input
        is_valid, error = near_verifier.validate_address(123)
        assert not is_valid
        assert "must be a non-empty string" in error
    
    def test_create_challenge_message(self, near_verifier):
        """Test NEAR challenge message creation"""
        nonce = "0x1234567890abcdef"
        account_id = "alice.testnet"
        
        message = near_verifier.create_challenge_message(nonce, account_id=account_id)
        
        assert "Sign in to MintroAI" in message
        assert f"Network: {near_verifier.config.network_id}" in message
        assert f"Nonce: {nonce}" in message
        assert f"Account: {account_id}" in message
        assert "Timestamp:" in message
    
    def test_create_challenge_message_without_account(self, near_verifier):
        """Test challenge message creation without account ID"""
        nonce = "0x1234567890abcdef"
        
        message = near_verifier.create_challenge_message(nonce)
        
        assert "Sign in to MintroAI" in message
        assert f"Nonce: {nonce}" in message
        assert "Account:" not in message
    
    def test_verify_ed25519_signature_valid(self, near_verifier, test_keypair):
        """Test valid ed25519 signature verification"""
        message = "Test message for signing"
        signature = sign_message_ed25519(message, test_keypair['private_key'])
        
        is_valid = near_verifier._verify_ed25519_signature(
            message,
            signature,
            test_keypair['public_key']
        )
        
        assert is_valid
    
    def test_verify_ed25519_signature_invalid(self, near_verifier, test_keypair):
        """Test invalid ed25519 signature verification"""
        message = "Test message for signing"
        wrong_message = "Different message"
        signature = sign_message_ed25519(message, test_keypair['private_key'])
        
        # Wrong message
        is_valid = near_verifier._verify_ed25519_signature(
            wrong_message,
            signature,
            test_keypair['public_key']
        )
        assert not is_valid
        
        # Wrong signature
        wrong_signature = sign_message_ed25519(wrong_message, test_keypair['private_key'])
        is_valid = near_verifier._verify_ed25519_signature(
            message,
            wrong_signature,
            test_keypair['public_key']
        )
        assert not is_valid
    
    def test_verify_ed25519_signature_with_near_prefix(self, near_verifier, test_keypair):
        """Test signature verification with NEAR public key prefix"""
        message = "Test message for signing"
        signature = sign_message_ed25519(message, test_keypair['private_key'])
        
        is_valid = near_verifier._verify_ed25519_signature(
            message,
            signature,
            test_keypair['near_public_key']  # With ed25519: prefix
        )
        
        assert is_valid
    
    @pytest.mark.asyncio
    async def test_verify_signature_not_initialized(self, near_verifier):
        """Test signature verification when verifier not initialized"""
        is_valid, error = await near_verifier.verify_signature(
            "alice.testnet",
            "test message",
            "fake_signature"
        )
        
        assert not is_valid
        assert "not initialized" in error
    
    @pytest.mark.asyncio
    async def test_verify_signature_invalid_address(self, near_verifier):
        """Test signature verification with invalid address"""
        near_verifier._connection_established = True  # Mock initialization
        
        is_valid, error = await near_verifier.verify_signature(
            "invalid@address",
            "test message",
            "fake_signature"
        )
        
        assert not is_valid
        assert "Invalid address" in error
    
    @pytest.mark.asyncio
    @patch('src.core.service.auth.protocols.near.Account')
    async def test_get_account_info_success(self, mock_account, near_verifier):
        """Test successful account info retrieval"""
        near_verifier._connection_established = True
        near_verifier.provider = MagicMock()
        
        # Mock account
        mock_account_instance = AsyncMock()
        mock_account_instance.startup = AsyncMock()
        mock_account_instance.fetch_state = AsyncMock(return_value={
            "storage_usage": 1000,
            "code_hash": "11111111111111111111111111111111"
        })
        mock_account_instance.get_balance = AsyncMock(return_value="1000000000000000000000000")
        mock_account_instance.get_access_keys = AsyncMock(return_value=[
            {"public_key": "ed25519:test123", "access_key": {"permission": "FullAccess"}}
        ])
        mock_account.return_value = mock_account_instance
        
        account_info = await near_verifier.get_account_info("alice.testnet")
        
        assert account_info is not None
        assert account_info["account_id"] == "alice.testnet"
        assert account_info["protocol"] == "near"
        assert account_info["network_id"] == "testnet"
        assert "balance" in account_info
        assert "storage_usage" in account_info
    
    @pytest.mark.asyncio
    @patch('src.core.service.auth.protocols.near.Account')
    async def test_get_account_info_not_found(self, mock_account, near_verifier):
        """Test account info retrieval for non-existent account"""
        near_verifier._connection_established = True
        near_verifier.provider = MagicMock()
        
        # Mock account to raise "does not exist" exception
        from src.core.service.auth.protocols.near import NEARException
        mock_account_instance = AsyncMock()
        mock_account_instance.startup = AsyncMock()
        mock_account_instance.fetch_state = AsyncMock(
            side_effect=NEARException("Account does not exist")
        )
        mock_account.return_value = mock_account_instance
        
        account_info = await near_verifier.get_account_info("nonexistent.testnet")
        
        assert account_info is None
    
    def test_generate_nonce(self, near_verifier):
        """Test nonce generation"""
        nonce1 = near_verifier.generate_nonce()
        nonce2 = near_verifier.generate_nonce()
        
        assert nonce1.startswith("0x")
        assert nonce2.startswith("0x")
        assert len(nonce1) == 66  # 0x + 64 hex chars
        assert len(nonce2) == 66
        assert nonce1 != nonce2  # Should be unique
    
    def test_get_protocol_info(self, near_verifier):
        """Test protocol info retrieval"""
        info = near_verifier.get_protocol_info()
        
        assert info["protocol"] == "near"
        assert info["network_id"] == "testnet"
        assert info["enabled"] is True


class TestNEARVerifierFactory:
    """Test suite for NEAR verifier factory function"""
    
    def test_create_near_verifier_testnet(self):
        """Test creating NEAR verifier for testnet"""
        verifier = create_near_verifier("testnet")
        
        assert isinstance(verifier, NEARVerifier)
        assert verifier.config.network_id == "testnet"
        assert "rpc.testnet.near.org" in verifier.config.rpc_urls[0]
    
    def test_create_near_verifier_mainnet(self):
        """Test creating NEAR verifier for mainnet"""
        verifier = create_near_verifier("mainnet")
        
        assert isinstance(verifier, NEARVerifier)
        assert verifier.config.network_id == "mainnet"
        assert "rpc.mainnet.near.org" in verifier.config.rpc_urls[0]
    
    def test_create_near_verifier_custom_rpc(self):
        """Test creating NEAR verifier with custom RPC URLs"""
        custom_rpcs = ["https://custom.rpc.url"]
        verifier = create_near_verifier("testnet", rpc_urls=custom_rpcs)
        
        assert verifier.config.rpc_urls == custom_rpcs
    
    def test_create_near_verifier_invalid_network(self):
        """Test creating NEAR verifier with invalid network"""
        with pytest.raises(ValueError, match="Unknown network_id"):
            create_near_verifier("invalid_network")
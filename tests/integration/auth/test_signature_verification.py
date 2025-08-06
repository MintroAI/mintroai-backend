import pytest
from eth_account.messages import encode_defunct
from eth_account import Account

from src.core.service.auth.signature_verification import SignatureVerificationService


@pytest.fixture
def test_wallet():
    """Create a test wallet for signature verification"""
    # Create a new random account for testing
    account = Account.create()
    return {
        'address': account.address,
        'key': account.key
    }


@pytest.fixture
def signature_service():
    """Create a signature verification service"""
    return SignatureVerificationService()


def test_verify_valid_signature(test_wallet, signature_service):
    """Test signature verification with a valid signature"""
    # Create a message
    message = "Sign in to MintroAI\nNonce: 0x1234567890"
    
    # Sign the message
    signable_message = encode_defunct(text=message)
    signed_message = Account.sign_message(signable_message, private_key=test_wallet['key'])
    
    # Verify the signature
    is_valid, error = signature_service.verify_signature(
        message=message,
        signature=signed_message.signature,
        claimed_address=test_wallet['address']
    )
    
    assert is_valid is True
    assert error is None


def test_verify_invalid_signature(test_wallet, signature_service):
    """Test signature verification with an invalid signature"""
    # Create a message
    message = "Sign in to MintroAI\nNonce: 0x1234567890"
    
    # Sign a different message
    different_message = "Different message"
    signable_message = encode_defunct(text=different_message)
    signed_message = Account.sign_message(signable_message, private_key=test_wallet['key'])
    
    # Verify the signature with the original message
    is_valid, error = signature_service.verify_signature(
        message=message,
        signature=signed_message.signature,
        claimed_address=test_wallet['address']
    )
    
    assert is_valid is False
    assert "Recovered address does not match claimed address" in error


def test_verify_wrong_address(test_wallet, signature_service):
    """Test signature verification with wrong address"""
    # Create a message
    message = "Sign in to MintroAI\nNonce: 0x1234567890"
    
    # Sign the message
    signable_message = encode_defunct(text=message)
    signed_message = Account.sign_message(signable_message, private_key=test_wallet['key'])
    
    # Create another wallet
    another_wallet = Account.create()
    
    # Verify the signature with a different address
    is_valid, error = signature_service.verify_signature(
        message=message,
        signature=signed_message.signature,
        claimed_address=another_wallet.address
    )
    
    assert is_valid is False
    assert "Recovered address does not match claimed address" in error


def test_verify_invalid_address_format(signature_service):
    """Test signature verification with invalid address format"""
    message = "Sign in to MintroAI\nNonce: 0x1234567890"
    signature = "0x1234567890"  # Dummy signature
    
    invalid_addresses = [
        "invalid",
        "0x123",  # too short
        "0x" + "1" * 39,  # too short (41 chars total)
        "1234567890" * 4,  # no 0x prefix
        "0x" + "g" * 40,  # invalid hex characters
    ]
    
    for address in invalid_addresses:
        is_valid, error = signature_service.verify_signature(
            message=message,
            signature=signature,
            claimed_address=address
        )
        
        assert is_valid is False
        assert any(["Invalid Ethereum address format" in error, "Invalid signature format" in error])


def test_verify_invalid_signature_format(test_wallet, signature_service):
    """Test signature verification with invalid signature format"""
    message = "Sign in to MintroAI\nNonce: 0x1234567890"
    
    invalid_signatures = [
        "invalid",
        "0x123",  # too short
        "not-hex-0x1234",
        "0x" + "g" * 130,  # invalid hex characters
    ]
    
    for signature in invalid_signatures:
        is_valid, error = signature_service.verify_signature(
            message=message,
            signature=signature,
            claimed_address=test_wallet['address']
        )
        
        assert is_valid is False
        assert "Invalid signature format" in error
#!/usr/bin/env python3
"""
Basic functionality test without external dependencies.
Tests core authentication functionality.
"""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.api.controller.auth.dto.input_dto import ChallengeRequestDto, VerifyRequestDto, ProtocolType
from src.api.controller.auth.dto.output_dto import ChallengeResponseDto, AuthResponseDto
from src.api.utils.validators import AddressValidator, SignatureValidator, RequestValidator
from src.core.service.auth.protocols.base import BlockchainProtocol


def test_dto_validation():
    """Test DTO validation works correctly."""
    print("🧪 Testing DTO validation...")
    
    try:
        # Test valid challenge request
        challenge_req = ChallengeRequestDto(
            wallet_address="0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
            protocol=ProtocolType.EVM
        )
        assert challenge_req.wallet_address == "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8"
        assert challenge_req.protocol == ProtocolType.EVM
        print("✅ Challenge request DTO validation passed")
        
        # Test valid verify request
        verify_req = VerifyRequestDto(
            wallet_address="alice.testnet",
            signature="test_signature",
            protocol=ProtocolType.NEAR,
            public_key="ed25519:test_public_key"
        )
        assert verify_req.protocol == ProtocolType.NEAR
        assert verify_req.public_key == "ed25519:test_public_key"
        print("✅ Verify request DTO validation passed")
        
        return True
        
    except Exception as e:
        print(f"❌ DTO validation failed: {e}")
        return False


def test_address_validation():
    """Test address validation for different protocols."""
    print("🧪 Testing address validation...")
    
    try:
        # Test EVM address validation
        valid_evm = "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8"
        invalid_evm = "invalid_address"
        
        assert AddressValidator.validate_evm_address(valid_evm) == True
        assert AddressValidator.validate_evm_address(invalid_evm) == False
        print("✅ EVM address validation passed")
        
        # Test NEAR address validation
        valid_near_named = "alice.testnet"
        valid_near_implicit = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        invalid_near = "invalid@near"
        
        assert AddressValidator.validate_near_address(valid_near_named) == True
        assert AddressValidator.validate_near_address(valid_near_implicit) == True
        assert AddressValidator.validate_near_address(invalid_near) == False
        print("✅ NEAR address validation passed")
        
        return True
        
    except Exception as e:
        print(f"❌ Address validation failed: {e}")
        return False


def test_signature_format_validation():
    """Test signature format validation."""
    print("🧪 Testing signature format validation...")
    
    try:
        # Test EVM signature format
        valid_evm_sig = "0x" + "a" * 130  # 65 bytes hex
        invalid_evm_sig = "invalid_signature"
        
        is_valid, _ = SignatureValidator.validate_signature_format(valid_evm_sig, BlockchainProtocol.EVM)
        assert is_valid == True
        
        is_valid, _ = SignatureValidator.validate_signature_format(invalid_evm_sig, BlockchainProtocol.EVM)
        assert is_valid == False
        print("✅ EVM signature format validation passed")
        
        # Test NEAR signature format
        valid_near_sig = "base58signature" * 10  # Valid length base58
        invalid_near_sig = "invalid@signature"
        
        is_valid, _ = SignatureValidator.validate_signature_format(valid_near_sig, BlockchainProtocol.NEAR)
        assert is_valid == True
        
        is_valid, _ = SignatureValidator.validate_signature_format(invalid_near_sig, BlockchainProtocol.NEAR)
        assert is_valid == False
        print("✅ NEAR signature format validation passed")
        
        return True
        
    except Exception as e:
        print(f"❌ Signature format validation failed: {e}")
        return False


def test_request_validator():
    """Test request validator functionality."""
    print("🧪 Testing request validator...")
    
    try:
        # Test protocol validation
        protocol = RequestValidator.validate_protocol("evm")
        assert protocol == BlockchainProtocol.EVM
        
        protocol = RequestValidator.validate_protocol("near")
        assert protocol == BlockchainProtocol.NEAR
        print("✅ Protocol validation passed")
        
        # Test address validation with protocol
        evm_address = RequestValidator.validate_wallet_address(
            "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8", 
            BlockchainProtocol.EVM
        )
        assert evm_address == "0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8"
        
        near_address = RequestValidator.validate_wallet_address(
            "alice.testnet", 
            BlockchainProtocol.NEAR
        )
        assert near_address == "alice.testnet"
        print("✅ Address validation with protocol passed")
        
        return True
        
    except Exception as e:
        print(f"❌ Request validator failed: {e}")
        return False


async def test_protocol_registry():
    """Test protocol registry functionality."""
    print("🧪 Testing protocol registry...")
    
    try:
        from src.core.service.auth.protocols.base import protocol_registry
        from src.core.service.auth.protocols.evm import create_evm_verifier
        from src.core.service.auth.protocols.near import create_near_verifier
        
        # Create and register verifiers
        evm_verifier = create_evm_verifier("mainnet", chain_id=1)
        protocol_registry.register(evm_verifier)
        
        near_verifier = create_near_verifier("testnet")
        protocol_registry.register(near_verifier)
        
        # Test registry
        supported_protocols = protocol_registry.get_supported_protocols()
        assert BlockchainProtocol.EVM in supported_protocols
        assert BlockchainProtocol.NEAR in supported_protocols
        
        # Test getting verifiers
        evm_v = protocol_registry.get_verifier(BlockchainProtocol.EVM)
        assert evm_v is not None
        
        near_v = protocol_registry.get_verifier(BlockchainProtocol.NEAR)
        assert near_v is not None
        
        print("✅ Protocol registry test passed")
        return True
        
    except Exception as e:
        print(f"❌ Protocol registry test failed: {e}")
        return False


def test_response_schemas():
    """Test response DTO schemas."""
    print("🧪 Testing response schemas...")
    
    try:
        # Test challenge response
        challenge_response = ChallengeResponseDto(
            nonce="0x1234567890abcdef",
            message="Sign in to MintroAI\nNonce: 0x1234567890abcdef",
            expires_in=300,
            protocol="evm"
        )
        assert challenge_response.nonce == "0x1234567890abcdef"
        assert challenge_response.expires_in == 300
        print("✅ Challenge response schema passed")
        
        # Test auth response
        auth_response = AuthResponseDto(
            access_token="jwt.access.token",
            refresh_token="jwt.refresh.token",
            token_type="bearer",
            expires_in=3600,
            wallet_address="0x742d35Cc6634C0532925a3b8D0C1a0e3A4b4e9C8",
            protocol="evm"
        )
        assert auth_response.token_type == "bearer"
        assert auth_response.expires_in == 3600
        print("✅ Auth response schema passed")
        
        return True
        
    except Exception as e:
        print(f"❌ Response schema test failed: {e}")
        return False


async def main():
    """Run all basic tests."""
    print("🚀 Starting basic functionality tests...\n")
    
    tests = [
        test_dto_validation,
        test_address_validation,
        test_signature_format_validation,
        test_request_validator,
        test_protocol_registry,
        test_response_schemas
    ]
    
    results = []
    for test in tests:
        if asyncio.iscoroutinefunction(test):
            result = await test()
        else:
            result = test()
        results.append(result)
        print()
    
    passed = sum(results)
    total = len(results)
    
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All basic functionality tests passed!")
        return True
    else:
        print("❌ Some tests failed!")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)

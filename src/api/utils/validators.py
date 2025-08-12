"""
Enhanced input validation utilities for API endpoints.
"""

import re
from typing import Optional, List, Dict, Any, Union
from pydantic import validator, ValidationError
from fastapi import HTTPException, status

from src.api.controller.auth.dto.error_responses import ErrorCode, ErrorDetail, ValidationErrorResponse
from src.core.service.auth.protocols.base import BlockchainProtocol


class ValidationException(Exception):
    """Custom validation exception with detailed error information."""
    
    def __init__(self, errors: List[Dict[str, Any]], status_code: int = 422):
        self.errors = errors
        self.status_code = status_code
        super().__init__(f"Validation failed: {len(errors)} errors")


class AddressValidator:
    """Validators for blockchain addresses."""
    
    @staticmethod
    def validate_evm_address(address: str) -> bool:
        """Validate EVM (Ethereum) address format."""
        if not address:
            return False
        
        # Remove 0x prefix if present
        addr = address.lower()
        if addr.startswith('0x'):
            addr = addr[2:]
        
        # Check if it's 40 hex characters
        if len(addr) != 40:
            return False
        
        # Check if all characters are valid hex
        return bool(re.match(r'^[0-9a-f]{40}$', addr))
    
    @staticmethod
    def validate_near_address(address: str) -> bool:
        """Validate NEAR protocol address format."""
        if not address:
            return False
        
        address = address.lower()
        
        # Implicit account (64 hex characters)
        if re.match(r'^[0-9a-f]{64}$', address):
            return True
        
        # Named account (subaccounts with dots)
        if re.match(r'^[a-z0-9]+([a-z0-9\-_]*[a-z0-9])?\.(near|testnet)$', address):
            return True
        
        # Top-level account (more strict - no underscores or hyphens for top-level)
        if re.match(r'^[a-z0-9]+$', address) and len(address) >= 2 and len(address) <= 64:
            return True
        
        return False
    
    @staticmethod
    def validate_address_for_protocol(address: str, protocol: BlockchainProtocol) -> tuple[bool, str]:
        """
        Validate address for specific protocol.
        Returns: (is_valid, error_message)
        """
        if not address or not address.strip():
            return False, "Address cannot be empty"
        
        address = address.strip()
        
        if protocol == BlockchainProtocol.EVM:
            if AddressValidator.validate_evm_address(address):
                return True, ""
            return False, "Invalid EVM address format. Expected 40 hex characters with optional 0x prefix."
        
        elif protocol == BlockchainProtocol.NEAR:
            if AddressValidator.validate_near_address(address):
                return True, ""
            return False, "Invalid NEAR address format. Expected implicit account (64 hex chars) or named account (name.near/testnet)."
        
        return False, f"Unsupported protocol: {protocol}"


class SignatureValidator:
    """Validators for cryptographic signatures."""
    
    @staticmethod
    def validate_signature_format(signature: str, protocol: BlockchainProtocol) -> tuple[bool, str]:
        """
        Validate signature format for specific protocol.
        Returns: (is_valid, error_message)
        """
        if not signature or not signature.strip():
            return False, "Signature cannot be empty"
        
        signature = signature.strip()
        
        if protocol == BlockchainProtocol.EVM:
            # EVM signatures are typically 65 bytes (130 hex chars) with optional 0x prefix
            sig = signature.lower()
            if sig.startswith('0x'):
                sig = sig[2:]
            
            if len(sig) != 130:
                return False, "Invalid EVM signature length. Expected 130 hex characters."
            
            if not re.match(r'^[0-9a-f]{130}$', sig):
                return False, "Invalid EVM signature format. Must be hex encoded."
            
            return True, ""
        
        elif protocol == BlockchainProtocol.NEAR:
            # NEAR signatures are base58 encoded, typically around 88-100 characters
            if len(signature) < 80 or len(signature) > 120:
                return False, "Invalid NEAR signature length. Expected 80-120 characters."
            
            # Basic base58 character check
            if not re.match(r'^[1-9A-HJ-NP-Za-km-z]+$', signature):
                return False, "Invalid NEAR signature format. Must be base58 encoded."
            
            return True, ""
        
        return False, f"Unsupported protocol: {protocol}"


class PublicKeyValidator:
    """Validators for public keys."""
    
    @staticmethod
    def validate_near_public_key(public_key: Optional[str]) -> tuple[bool, str]:
        """
        Validate NEAR public key format.
        Returns: (is_valid, error_message)
        """
        if not public_key:
            return True, ""  # Public key is optional for NEAR
        
        public_key = public_key.strip()
        
        # NEAR public keys are typically ed25519: prefixed base58 strings
        if not public_key.startswith('ed25519:'):
            return False, "NEAR public key must start with 'ed25519:' prefix"
        
        key_part = public_key[8:]  # Remove 'ed25519:' prefix
        
        if len(key_part) < 40 or len(key_part) > 50:
            return False, "Invalid NEAR public key length"
        
        # Basic base58 character check
        if not re.match(r'^[1-9A-HJ-NP-Za-km-z]+$', key_part):
            return False, "Invalid NEAR public key format. Must be base58 encoded."
        
        return True, ""


class RequestValidator:
    """Main request validator with comprehensive checks."""
    
    @staticmethod
    def validate_protocol(protocol: str) -> BlockchainProtocol:
        """Validate and convert protocol string to enum."""
        if not protocol:
            raise ValidationException([{
                'field': 'protocol',
                'code': ErrorCode.MISSING_FIELD,
                'message': 'Protocol is required'
            }])
        
        try:
            return BlockchainProtocol(protocol.lower())
        except ValueError:
            supported = [p.value for p in BlockchainProtocol]
            raise ValidationException([{
                'field': 'protocol',
                'code': ErrorCode.UNSUPPORTED_PROTOCOL,
                'message': f'Unsupported protocol: {protocol}. Supported protocols: {supported}'
            }])
    
    @staticmethod
    def validate_wallet_address(address: str, protocol: BlockchainProtocol) -> str:
        """Validate wallet address for specific protocol."""
        if not address:
            raise ValidationException([{
                'field': 'wallet_address',
                'code': ErrorCode.MISSING_FIELD,
                'message': 'Wallet address is required'
            }])
        
        is_valid, error_msg = AddressValidator.validate_address_for_protocol(address, protocol)
        if not is_valid:
            raise ValidationException([{
                'field': 'wallet_address',
                'code': ErrorCode.INVALID_ADDRESS,
                'message': error_msg
            }])
        
        return address.strip()
    
    @staticmethod
    def validate_signature(signature: str, protocol: BlockchainProtocol) -> str:
        """Validate signature for specific protocol."""
        if not signature:
            raise ValidationException([{
                'field': 'signature',
                'code': ErrorCode.MISSING_FIELD,
                'message': 'Signature is required'
            }])
        
        is_valid, error_msg = SignatureValidator.validate_signature_format(signature, protocol)
        if not is_valid:
            raise ValidationException([{
                'field': 'signature',
                'code': ErrorCode.INVALID_SIGNATURE,
                'message': error_msg
            }])
        
        return signature.strip()
    
    @staticmethod
    def validate_public_key(public_key: Optional[str], protocol: BlockchainProtocol) -> Optional[str]:
        """Validate public key for specific protocol."""
        if protocol == BlockchainProtocol.NEAR:
            is_valid, error_msg = PublicKeyValidator.validate_near_public_key(public_key)
            if not is_valid:
                raise ValidationException([{
                    'field': 'public_key',
                    'code': ErrorCode.INVALID_FORMAT,
                    'message': error_msg
                }])
        
        return public_key.strip() if public_key else None
    
    @staticmethod
    def validate_token(token: str, token_type: str = "token") -> str:
        """Validate JWT token format."""
        if not token:
            raise ValidationException([{
                'field': token_type,
                'code': ErrorCode.MISSING_FIELD,
                'message': f'{token_type.capitalize()} is required'
            }])
        
        token = token.strip()
        
        # Basic JWT format check (3 parts separated by dots)
        parts = token.split('.')
        if len(parts) != 3:
            raise ValidationException([{
                'field': token_type,
                'code': ErrorCode.INVALID_TOKEN,
                'message': f'Invalid {token_type} format. Expected JWT format.'
            }])
        
        return token


def create_validation_error_response(validation_errors: List[Dict[str, Any]]) -> ValidationErrorResponse:
    """Create standardized validation error response."""
    main_error = ErrorDetail(
        code=ErrorCode.INVALID_INPUT,
        message=f"Validation failed for {len(validation_errors)} field(s)",
        details="Please check the validation_errors field for specific issues"
    )
    
    return ValidationErrorResponse(
        error=main_error,
        validation_errors=validation_errors
    )


def handle_pydantic_validation_error(exc: ValidationError) -> ValidationErrorResponse:
    """Convert Pydantic validation error to standardized format."""
    validation_errors = []
    
    for error in exc.errors():
        field = '.'.join(str(loc) for loc in error['loc'])
        validation_errors.append({
            'field': field,
            'code': ErrorCode.INVALID_FORMAT,
            'message': error['msg'],
            'input': error.get('input')
        })
    
    return create_validation_error_response(validation_errors)


def validation_exception_handler(request, exc: ValidationException) -> HTTPException:
    """Convert ValidationException to HTTPException with proper format."""
    response = create_validation_error_response(exc.errors)
    
    raise HTTPException(
        status_code=exc.status_code,
        detail=response.dict()
    )

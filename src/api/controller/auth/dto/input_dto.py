"""
Input DTOs for authentication API endpoints.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, Union, Dict, Any
from enum import Enum


class ProtocolType(str, Enum):
    """Supported blockchain protocols."""
    EVM = "evm"
    NEAR = "near"


class NEARSignatureDto(BaseModel):
    """DTO for NEAR signMessage signature object."""
    
    accountId: str = Field(..., description="NEAR account ID")
    publicKey: str = Field(..., description="Public key with ed25519: prefix")
    signature: str = Field(..., description="Base64-encoded signature")
    
    @validator('accountId')
    def validate_account_id(cls, v):
        if not v or not v.strip():
            raise ValueError('Account ID cannot be empty')
        return v.strip()
    
    @validator('publicKey')
    def validate_public_key(cls, v):
        if not v or not v.strip():
            raise ValueError('Public key cannot be empty')
        if not v.startswith('ed25519:'):
            raise ValueError('Public key must have ed25519: prefix')
        return v.strip()
    
    @validator('signature')
    def validate_signature(cls, v):
        if not v or not v.strip():
            raise ValueError('Signature cannot be empty')
        return v.strip()


class ChallengeRequestDto(BaseModel):
    """DTO for challenge creation request."""
    
    wallet_address: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Wallet address for the specified protocol"
    )
    protocol: ProtocolType = Field(
        ...,
        description="Blockchain protocol (evm or near)"
    )
    
    @validator('wallet_address')
    def validate_wallet_address(cls, v):
        if not v or not v.strip():
            raise ValueError('Wallet address cannot be empty')
        return v.strip()
    
    @validator('protocol')
    def validate_protocol(cls, v):
        if v not in ProtocolType:
            raise ValueError(f'Unsupported protocol: {v}')
        return v


class VerifyRequestDto(BaseModel):
    """DTO for signature verification request."""
    
    wallet_address: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Wallet address that signed the challenge"
    )
    signature: Union[str, NEARSignatureDto] = Field(
        ...,
        description="Signature - string for EVM, object for NEAR signMessage"
    )
    protocol: ProtocolType = Field(
        ...,
        description="Blockchain protocol (evm or near)"
    )
    public_key: Optional[str] = Field(
        None,
        description="Public key for NEAR protocol (optional but recommended)"
    )
    nonce: str = Field(
        ...,
        description="Challenge nonce that was signed"
    )
    recipient: Optional[str] = Field(
        None,
        description="App domain/recipient for NEAR signMessage (optional)"
    )
    
    @validator('wallet_address')
    def validate_wallet_address(cls, v):
        if not v or not v.strip():
            raise ValueError('Wallet address cannot be empty')
        return v.strip()
    
    @validator('signature')
    def validate_signature(cls, v, values):
        protocol = values.get('protocol')
        
        if protocol == ProtocolType.NEAR:
            # For NEAR, signature can be either string or object
            if isinstance(v, dict):
                # Convert dict to NEARSignatureDto for validation
                try:
                    return NEARSignatureDto(**v)
                except Exception as e:
                    raise ValueError(f'Invalid NEAR signature object: {str(e)}')
            elif isinstance(v, str):
                if not v or not v.strip():
                    raise ValueError('Signature cannot be empty')
                return v.strip()
            else:
                raise ValueError('NEAR signature must be string or object')
        
        elif protocol == ProtocolType.EVM:
            # For EVM, signature must be string
            if not isinstance(v, str):
                raise ValueError('EVM signature must be string')
            if not v or not v.strip():
                raise ValueError('Signature cannot be empty')
            return v.strip()
        
        return v
    
    @validator('public_key')
    def validate_public_key(cls, v, values):
        if v and not v.strip():
            raise ValueError('Public key cannot be empty string')
        return v.strip() if v else None
    
    @validator('nonce')
    def validate_nonce(cls, v):
        if not v or not v.strip():
            raise ValueError('Nonce cannot be empty')
        return v.strip()
    
    @validator('recipient')
    def validate_recipient(cls, v, values):
        protocol = values.get('protocol')
        
        # For NEAR signMessage, recipient is recommended
        if protocol == ProtocolType.NEAR and isinstance(values.get('signature'), NEARSignatureDto):
            if not v:
                # Default to localhost for development
                return "http://localhost:3000"
        
        return v.strip() if v else None


class RefreshTokenRequestDto(BaseModel):
    """DTO for token refresh request."""
    
    refresh_token: str = Field(
        ...,
        min_length=1,
        description="Valid refresh token"
    )
    
    @validator('refresh_token')
    def validate_refresh_token(cls, v):
        if not v or not v.strip():
            raise ValueError('Refresh token cannot be empty')
        return v.strip()


class LogoutRequestDto(BaseModel):
    """DTO for logout request."""
    
    access_token: Optional[str] = Field(
        None,
        description="Access token to blacklist (optional)"
    )
    refresh_token: Optional[str] = Field(
        None,
        description="Refresh token to blacklist (optional)"
    )
    logout_all: bool = Field(
        False,
        description="Logout from all devices"
    )
    
    @validator('access_token')
    def validate_access_token(cls, v):
        if v and not v.strip():
            raise ValueError('Access token cannot be empty string')
        return v.strip() if v else None
    
    @validator('refresh_token')
    def validate_refresh_token(cls, v):
        if v and not v.strip():
            raise ValueError('Refresh token cannot be empty string')
        return v.strip() if v else None

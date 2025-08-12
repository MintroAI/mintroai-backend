"""
Input DTOs for authentication API endpoints.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional
from enum import Enum


class ProtocolType(str, Enum):
    """Supported blockchain protocols."""
    EVM = "evm"
    NEAR = "near"


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
    signature: str = Field(
        ...,
        min_length=1,
        description="Signature of the challenge message"
    )
    protocol: ProtocolType = Field(
        ...,
        description="Blockchain protocol (evm or near)"
    )
    public_key: Optional[str] = Field(
        None,
        description="Public key for NEAR protocol (optional but recommended)"
    )
    
    @validator('wallet_address')
    def validate_wallet_address(cls, v):
        if not v or not v.strip():
            raise ValueError('Wallet address cannot be empty')
        return v.strip()
    
    @validator('signature')
    def validate_signature(cls, v):
        if not v or not v.strip():
            raise ValueError('Signature cannot be empty')
        return v.strip()
    
    @validator('public_key')
    def validate_public_key(cls, v, values):
        if v and not v.strip():
            raise ValueError('Public key cannot be empty string')
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

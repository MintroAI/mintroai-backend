"""
Request DTOs for API endpoints.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional
import re


class ChallengeRequestDTO(BaseModel):
    """Request model for creating authentication challenge."""
    
    wallet_address: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Wallet address to authenticate"
    )
    protocol: str = Field(
        ...,
        description="Blockchain protocol (evm, near)"
    )
    
    @validator('protocol')
    def validate_protocol(cls, v):
        """Validate protocol format."""
        if v.lower() not in ['evm', 'near']:
            raise ValueError(f"Unsupported protocol: {v}. Supported: evm, near")
        return v.lower()
    
    @validator('wallet_address')
    def validate_wallet_address(cls, v, values):
        """Basic wallet address validation."""
        if not v or not v.strip():
            raise ValueError("Wallet address cannot be empty")
        
        # Get protocol for address validation
        protocol = values.get('protocol', '').lower()
        
        if protocol == 'evm':
            # EVM address validation (0x + 40 hex chars)
            if not re.match(r'^0x[a-fA-F0-9]{40}$', v):
                raise ValueError("Invalid EVM address format")
        elif protocol == 'near':
            # NEAR address validation (basic)
            if len(v) < 2 or len(v) > 64:
                raise ValueError("Invalid NEAR address length")
        
        return v.strip()


class VerifyRequestDTO(BaseModel):
    """Request model for verifying signed challenge."""
    
    wallet_address: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Wallet address that signed the challenge"
    )
    signature: str = Field(
        ...,
        min_length=1,
        description="Signature of the challenge message"
    )
    protocol: str = Field(
        ...,
        description="Blockchain protocol (evm, near)"
    )
    public_key: Optional[str] = Field(
        None,
        description="Public key (optional for NEAR, required for some EVM cases)"
    )
    
    @validator('protocol')
    def validate_protocol(cls, v):
        """Validate protocol format."""
        if v.lower() not in ['evm', 'near']:
            raise ValueError(f"Unsupported protocol: {v}. Supported: evm, near")
        return v.lower()
    
    @validator('signature')
    def validate_signature(cls, v):
        """Validate signature format."""
        if not v or not v.strip():
            raise ValueError("Signature cannot be empty")
        return v.strip()


class RefreshTokenRequestDTO(BaseModel):
    """Request model for refreshing access token."""
    
    refresh_token: str = Field(
        ...,
        min_length=1,
        description="Valid refresh token"
    )
    
    @validator('refresh_token')
    def validate_refresh_token(cls, v):
        """Validate refresh token format."""
        if not v or not v.strip():
            raise ValueError("Refresh token cannot be empty")
        return v.strip()


class LogoutRequestDTO(BaseModel):
    """Request model for user logout."""
    
    access_token: Optional[str] = Field(
        None,
        description="Access token to invalidate (optional if provided in header)"
    )
    refresh_token: Optional[str] = Field(
        None,
        description="Refresh token to invalidate"
    )
    logout_all: bool = Field(
        False,
        description="Logout from all sessions"
    )

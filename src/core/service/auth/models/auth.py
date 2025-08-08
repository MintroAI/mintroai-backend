"""
Authentication request and response models for multi-protocol wallet authentication.
"""

from pydantic import BaseModel, Field
from typing import Optional


class VerifyRequest(BaseModel):
    """Request model for challenge verification"""
    wallet_address: str = Field(..., description="Wallet address or account ID that signed the challenge")
    signature: str = Field(..., description="Signature of the challenge message")
    protocol: str = Field(default="evm", description="Blockchain protocol (evm, near, etc.)")
    public_key: Optional[str] = Field(None, description="Public key (required for NEAR protocol)")

    class Config:
        json_schema_extra = {
            "example": {
                "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                "signature": "0x...",
                "protocol": "evm"
            }
        }


class AuthResponse(BaseModel):
    """Response model for successful authentication"""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration time in seconds")

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "token_type": "bearer",
                "expires_in": 1800
            }
        }


class RefreshTokenRequest(BaseModel):
    """Request model for token refresh"""
    refresh_token: str = Field(..., description="Refresh token")

    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            }
        }


class LogoutRequest(BaseModel):
    """Request model for logout"""
    refresh_token: Optional[str] = Field(None, description="Refresh token to blacklist")

    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            }
        }
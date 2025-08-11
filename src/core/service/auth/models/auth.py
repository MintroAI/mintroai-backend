"""
Authentication request/response models for multi-protocol wallet authentication.
These models define the API contract for authentication endpoints.
"""

from pydantic import BaseModel, Field
from typing import Optional


class VerifyRequest(BaseModel):
    """Request model for challenge verification"""
    wallet_address: str = Field(..., description="Wallet address or account ID")
    signature: str = Field(..., description="Signature of the challenge message")
    protocol: str = Field(..., description="Blockchain protocol (evm, near)")
    public_key: Optional[str] = Field(None, description="Public key (required for NEAR offline verification)")
    
    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                    "signature": "0x1234567890abcdef...",
                    "protocol": "evm"
                },
                {
                    "wallet_address": "alice.testnet",
                    "signature": "3yMApqCuCjXDWPrbjfR5mjCPTHqFG8Pux1TxQHqVUVVizMV1BB",
                    "protocol": "near",
                    "public_key": "ed25519:H9k5eiU4xXyKdKMLieuqbpd5MbVw9SmW6VtqBJLuSGNv"
                }
            ]
        }


class AuthResponse(BaseModel):
    """Response model for successful authentication"""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800
            }
        }


class RefreshTokenRequest(BaseModel):
    """Request model for token refresh"""
    refresh_token: str = Field(..., description="Valid refresh token")
    
    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class LogoutRequest(BaseModel):
    """Request model for logout"""
    refresh_token: Optional[str] = Field(None, description="Refresh token to blacklist")
    
    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class ProtocolInfo(BaseModel):
    """Protocol information model"""
    protocol: str = Field(..., description="Protocol name")
    network_id: str = Field(..., description="Network identifier")
    enabled: bool = Field(..., description="Whether protocol is enabled")
    
    class Config:
        json_schema_extra = {
            "example": {
                "protocol": "near",
                "network_id": "testnet",
                "enabled": True
            }
        }

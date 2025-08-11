from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional


class ChallengeStatus(str, Enum):
    PENDING = "pending"
    USED = "used"
    EXPIRED = "expired"
    VERIFIED = "verified"
    INVALID = "invalid"


class Challenge(BaseModel):
    """Challenge model for wallet authentication"""
    nonce: str = Field(..., description="Unique nonce for the challenge")
    wallet_address: str = Field(..., description="Wallet address or account ID")
    protocol: str = Field(default="evm", description="Blockchain protocol (evm, near)")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    status: ChallengeStatus = Field(default=ChallengeStatus.PENDING)
    message: Optional[str] = Field(None, description="Challenge message to be signed")

    def is_expired(self) -> bool:
        """Check if the challenge has expired"""
        return datetime.now(timezone.utc) > self.expires_at

    class Config:
        json_schema_extra = {
            "example": {
                "nonce": "0x1234567890abcdef",
                "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                "timestamp": "2024-02-06T10:00:00Z",
                "expires_at": "2024-02-06T10:05:00Z",
                "status": "pending",
                "message": "Sign in to MintroAI\nNonce: 0x1234567890abcdef"
            }
        }


class ChallengeRequest(BaseModel):
    """Request model for challenge generation"""
    wallet_address: str = Field(..., description="Wallet address or account ID to generate challenge for")
    protocol: str = Field(default="evm", description="Blockchain protocol (evm, near)")

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                    "protocol": "evm"
                },
                {
                    "wallet_address": "alice.testnet",
                    "protocol": "near"
                }
            ]
        }


class ChallengeResponse(BaseModel):
    """Response model for challenge generation"""
    nonce: str = Field(..., description="Generated nonce")
    message: str = Field(..., description="Message to be signed")
    expires_in: int = Field(..., description="Expiration time in seconds")

    class Config:
        json_schema_extra = {
            "example": {
                "nonce": "0x1234567890abcdef",
                "message": "Sign in to MintroAI\nNonce: 0x1234567890abcdef",
                "expires_in": 300
            }
        }
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"


class TokenPayload(BaseModel):
    """JWT token payload structure"""
    wallet_address: str = Field(..., description="User's wallet address")
    exp: datetime = Field(..., description="Token expiration timestamp")
    iat: datetime = Field(..., description="Token issued at timestamp")
    type: TokenType = Field(..., description="Token type (access or refresh)")
    jti: str = Field(..., description="Unique token identifier for blacklisting")


class TokenResponse(BaseModel):
    """Response model for token generation"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires


class TokenBlacklist(BaseModel):
    """Model for blacklisted tokens"""
    jti: str
    exp: datetime
    blacklisted_at: datetime = Field(default_factory=datetime.utcnow)
    reason: Optional[str] = None
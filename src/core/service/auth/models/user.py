"""
User model for persistent database storage
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class UserTier(str, Enum):
    """User tier/subscription level"""
    FREE = "free"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


class User(BaseModel):
    """User database model"""
    id: Optional[UUID] = None
    wallet_address: str
    protocol: str  # 'evm' or 'near'
    first_login_at: datetime
    last_login_at: datetime
    login_count: int = Field(default=0, ge=0)
    challenge_count: int = Field(default=0, ge=0)
    user_tier: UserTier = UserTier.FREE
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v)
        }
        use_enum_values = True



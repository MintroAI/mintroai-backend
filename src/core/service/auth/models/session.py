from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class SessionStatus(str, Enum):
    """User session status"""
    ACTIVE = "active"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"


class DeviceInfo(BaseModel):
    """Information about the device used for authentication"""
    user_agent: str
    ip_address: str
    device_id: Optional[str] = None  # Device-specific identifier if available


class UserSession(BaseModel):
    """User session information"""
    id: UUID = Field(default_factory=uuid4)
    wallet_address: str
    device_info: DeviceInfo
    status: SessionStatus = SessionStatus.ACTIVE
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_active_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    invalidated_at: Optional[datetime] = None
    invalidation_reason: Optional[str] = None

    def update_activity(self) -> None:
        """Update last activity timestamp"""
        self.last_active_at = datetime.now(timezone.utc)

    def invalidate(self, reason: str) -> None:
        """Invalidate the session"""
        self.status = SessionStatus.INVALIDATED
        self.invalidated_at = datetime.now(timezone.utc)
        self.invalidation_reason = reason

    @property
    def is_active(self) -> bool:
        """Check if session is active"""
        return self.status == SessionStatus.ACTIVE
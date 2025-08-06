from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AuthEventType(str, Enum):
    """Types of authentication events"""
    CHALLENGE_REQUESTED = "challenge_requested"
    CHALLENGE_VERIFIED = "challenge_verified"
    CHALLENGE_FAILED = "challenge_failed"
    TOKEN_GENERATED = "token_generated"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_REVOKED = "token_revoked"
    SESSION_CREATED = "session_created"
    SESSION_INVALIDATED = "session_invalidated"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    SENSITIVE_OPERATION = "sensitive_operation"


class AuthEventStatus(str, Enum):
    """Status of authentication events"""
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"


class AuthEventContext(BaseModel):
    """Additional context for authentication events"""
    ip_address: str
    user_agent: Optional[str] = None
    session_id: Optional[UUID] = None
    device_id: Optional[str] = None
    failure_reason: Optional[str] = None
    operation_type: Optional[str] = None


class AuthAuditLog(BaseModel):
    """Audit log entry for authentication events"""
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: AuthEventType
    status: AuthEventStatus
    wallet_address: str
    context: AuthEventContext

    @classmethod
    def create(
        cls,
        event_type: AuthEventType,
        status: AuthEventStatus,
        wallet_address: str,
        ip_address: str,
        user_agent: Optional[str] = None,
        session_id: Optional[UUID] = None,
        device_id: Optional[str] = None,
        failure_reason: Optional[str] = None,
        operation_type: Optional[str] = None
    ) -> "AuthAuditLog":
        """Create a new audit log entry"""
        return cls(
            event_type=event_type,
            status=status,
            wallet_address=wallet_address,
            context=AuthEventContext(
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                device_id=device_id,
                failure_reason=failure_reason,
                operation_type=operation_type
            )
        )
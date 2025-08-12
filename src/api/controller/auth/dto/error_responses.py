"""
Standardized error response DTOs for authentication API.
"""

from pydantic import BaseModel, Field, field_serializer
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ErrorCode(str, Enum):
    """Standard error codes for API responses."""
    
    # Validation errors
    INVALID_INPUT = "INVALID_INPUT"
    MISSING_FIELD = "MISSING_FIELD"
    INVALID_FORMAT = "INVALID_FORMAT"
    
    # Authentication errors
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    EXPIRED_CHALLENGE = "EXPIRED_CHALLENGE"
    CHALLENGE_NOT_FOUND = "CHALLENGE_NOT_FOUND"
    INVALID_TOKEN = "INVALID_TOKEN"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    
    # Protocol errors
    UNSUPPORTED_PROTOCOL = "UNSUPPORTED_PROTOCOL"
    INVALID_ADDRESS = "INVALID_ADDRESS"
    RPC_ERROR = "RPC_ERROR"
    
    # Rate limiting
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    IP_BLOCKED = "IP_BLOCKED"
    
    # System errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class ErrorDetail(BaseModel):
    """Detailed error information."""
    
    code: ErrorCode = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[str] = Field(None, description="Additional error details")
    field: Optional[str] = Field(None, description="Field name for validation errors")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    request_id: Optional[str] = Field(None, description="Request ID for tracking")
    
    @field_serializer('timestamp')
    def serialize_timestamp(self, timestamp: datetime) -> str:
        """Serialize datetime to ISO format with Z suffix."""
        return timestamp.isoformat() + "Z"


class ErrorResponse(BaseModel):
    """Standard error response format."""
    
    error: ErrorDetail = Field(..., description="Error details")
    status_code: int = Field(..., description="HTTP status code")


class ValidationErrorResponse(BaseModel):
    """Validation error response with multiple field errors."""
    
    error: ErrorDetail = Field(..., description="Main error details")
    validation_errors: list[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of field validation errors"
    )
    status_code: int = Field(422, description="HTTP status code")


class RateLimitErrorResponse(BaseModel):
    """Rate limit error response with retry information."""
    
    error: ErrorDetail = Field(..., description="Error details")
    retry_after: int = Field(..., description="Seconds to wait before retry")
    limit: int = Field(..., description="Rate limit threshold")
    remaining: int = Field(0, description="remaining requests")
    reset_time: datetime = Field(..., description="When the rate limit resets")
    status_code: int = Field(429, description="HTTP status code")
    
    @field_serializer('reset_time')
    def serialize_reset_time(self, reset_time: datetime) -> str:
        """Serialize datetime to ISO format with Z suffix."""
        return reset_time.isoformat() + "Z"

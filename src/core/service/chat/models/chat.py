"""
Chat models for request/response handling
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any
from enum import Enum
from datetime import datetime


class ChatMode(str, Enum):
    """Supported chat modes"""
    TOKEN = "token"
    VESTING = "vesting"
    GENERAL = "general"


class UserContext(BaseModel):
    """User context for chat interactions"""
    wallet_address: Optional[str] = None
    is_authenticated: bool = False
    message_count: Optional[int] = None
    user_type: str = Field(default="guest", description="User type: guest, authenticated, premium")
    wallet_type: Optional[str] = None  # 'evm' or 'near'
    
    @validator('user_type')
    def validate_user_type(cls, v):
        if v not in ['guest', 'authenticated', 'premium']:
            raise ValueError('User type must be guest, authenticated, or premium')
        return v


class ChatRequest(BaseModel):
    """Chat request model"""
    sessionId: str = Field(..., description="Unique session identifier")
    chatInput: str = Field(..., min_length=1, max_length=4000, description="User's message")
    mode: ChatMode = Field(..., description="Chat mode: token, vesting, or general")
    userContext: Optional[UserContext] = None
    
    @validator('sessionId')
    def validate_session_id(cls, v):
        if not v or not v.strip():
            raise ValueError('Session ID cannot be empty')
        # Basic UUID format check
        if len(v) < 10:
            raise ValueError('Invalid session ID format')
        return v.strip()
    
    @validator('chatInput')
    def validate_chat_input(cls, v):
        if not v or not v.strip():
            raise ValueError('Chat input cannot be empty')
        return v.strip()


class RateLimitInfo(BaseModel):
    """Rate limit information"""
    remaining: int = Field(..., ge=0, description="Remaining requests")
    reset_time: str = Field(..., description="Time when rate limit resets")
    limit: int = Field(..., gt=0, description="Total rate limit")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class ChatResponse(BaseModel):
    """Chat response model"""
    output: Optional[str] = Field(None, description="AI response message")
    message: Optional[str] = Field(None, description="Alternative response field")
    sessionId: str = Field(..., description="Session identifier")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    rateLimitInfo: Optional[RateLimitInfo] = None
    error: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class ChatErrorResponse(BaseModel):
    """Error response for chat interactions"""
    error: str = Field(..., description="Error message")
    code: int = Field(..., description="Error code")
    details: Optional[Dict[str, Any]] = None
    rateLimitInfo: Optional[RateLimitInfo] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class ChatInteractionLog(BaseModel):
    """Model for logging chat interactions"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    session_id: str
    wallet_address: Optional[str] = None
    is_authenticated: bool = False
    chat_mode: str
    message_length: int
    response_success: bool
    duration_seconds: float
    client_ip: str
    user_agent: Optional[str] = None
    error_message: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }

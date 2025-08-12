"""
Output DTOs for authentication API endpoints.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ChallengeResponseDto(BaseModel):
    """DTO for challenge creation response."""
    
    nonce: str = Field(..., description="Unique challenge nonce")
    message: str = Field(..., description="Message to be signed by wallet")
    expires_in: int = Field(..., description="Challenge expiration time in seconds")
    protocol: str = Field(..., description="Protocol used for this challenge")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class AuthResponseDto(BaseModel):
    """DTO for successful authentication response."""
    
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration time in seconds")
    wallet_address: str = Field(..., description="Authenticated wallet address")
    protocol: str = Field(..., description="Authentication protocol used")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class TokenRefreshResponseDto(BaseModel):
    """DTO for token refresh response."""
    
    access_token: str = Field(..., description="New JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration time in seconds")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class LogoutResponseDto(BaseModel):
    """DTO for logout response."""
    
    success: bool = Field(True, description="Logout success status")
    message: str = Field(default="Successfully logged out", description="Logout message")
    logged_out_tokens: int = Field(0, description="Number of tokens blacklisted")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class SessionStatusResponseDto(BaseModel):
    """DTO for session status response."""
    
    valid: bool = Field(..., description="Whether the session is valid")
    wallet_address: Optional[str] = Field(None, description="Authenticated wallet address")
    protocol: Optional[str] = Field(None, description="Authentication protocol")
    expires_at: Optional[datetime] = Field(None, description="Token expiration time")
    remaining_seconds: Optional[int] = Field(None, description="Remaining token validity in seconds")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class ProtocolInfo(BaseModel):
    """Information about a supported protocol."""
    
    name: str = Field(..., description="Protocol name")
    enabled: bool = Field(..., description="Whether protocol is enabled")
    network: Optional[str] = Field(None, description="Network name (mainnet, testnet, etc.)")
    chain_id: Optional[int] = Field(None, description="Chain ID for EVM protocols")
    rpc_status: str = Field(..., description="RPC connection status")
    features: List[str] = Field(default_factory=list, description="Supported features")


class ProtocolsResponseDto(BaseModel):
    """DTO for supported protocols response."""
    
    protocols: List[ProtocolInfo] = Field(..., description="List of supported protocols")
    total_count: int = Field(..., description="Total number of protocols")
    enabled_count: int = Field(..., description="Number of enabled protocols")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class AccountInfoResponseDto(BaseModel):
    """DTO for account information response."""
    
    address: str = Field(..., description="Account address")
    protocol: str = Field(..., description="Protocol name")
    valid: bool = Field(..., description="Whether address is valid")
    network: Optional[str] = Field(None, description="Network name")
    account_type: Optional[str] = Field(None, description="Account type (e.g., implicit, named)")
    balance: Optional[str] = Field(None, description="Account balance if available")
    last_activity: Optional[datetime] = Field(None, description="Last known activity")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class HealthCheckResponseDto(BaseModel):
    """DTO for health check response."""
    
    status: str = Field(..., description="Overall health status")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Health check timestamp")
    protocols: Dict[str, Dict[str, Any]] = Field(..., description="Protocol-specific health info")
    services: Dict[str, str] = Field(..., description="Service health status")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }

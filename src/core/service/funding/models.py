"""Models for funding service."""

from typing import Dict, Optional
from pydantic import BaseModel, Field


class FundingRequest(BaseModel):
    """Request model for funding an address."""
    address: str = Field(..., description="The derived address to fund")
    chain_id: str = Field(..., description="The target chain ID")


class BalanceCheckRequest(BaseModel):
    """Request model for checking address balance."""
    address: str = Field(..., description="The address to check")
    chain_id: str = Field(..., description="The chain ID")


class FundingResponse(BaseModel):
    """Response model for funding operation."""
    success: bool
    funded: bool
    transactionHash: Optional[str] = None  # Frontend expects camelCase
    amount: str = "0"  # Amount funded or "0" if not funded
    message: str
    error: Optional[str] = None  # Error details if failed


class BalanceResponse(BaseModel):
    """Response model for balance check."""
    success: bool
    address: str
    chain_id: str
    balance: str
    network: str


class NetworkBalance(BaseModel):
    """Network balance information."""
    network: str
    balance: Optional[str] = None
    funding_amount: str
    can_fund: Optional[bool] = None
    error: Optional[str] = None


class FundingStatus(BaseModel):
    """Funding service status."""
    configured: bool
    message: Optional[str] = None
    funder_address: Optional[str] = None
    balances: Optional[Dict[str, NetworkBalance]] = None

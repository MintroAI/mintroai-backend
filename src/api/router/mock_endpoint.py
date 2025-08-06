from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()

class MockRequest(BaseModel):
    wallet_address: str = Field(..., description="Ethereum wallet address", pattern="^0x[a-fA-F0-9]{40}$")
    signature: str = Field(..., description="Signed message")

    class Config:
        json_schema_extra = {
            "example": {
                "wallet_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                "signature": "0x..."
            }
        }

@router.post("/test/wallet-verify")
async def test_wallet_verify(request: MockRequest):
    """
    Mock endpoint for testing rate limiting and validation
    This endpoint simulates wallet verification process
    """
    # Simulate verification failure for testing rate limiting
    raise HTTPException(
        status_code=401,
        detail="Invalid wallet signature"
    )
"""Funding router for Chain Signatures."""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from src.api.controller.funding.funding_controller import FundingController
from src.core.service.funding.models import (
    FundingRequest,
    FundingResponse,
    BalanceResponse,
    FundingStatus
)
from src.core.service.auth.jwt_service import JWTService
from src.infra.config.redis import get_redis
from src.core.logger.logger import logger


# Security scheme
security = HTTPBearer()

# Create router  
router = APIRouter(
    prefix="/api/v1",  # Changed to /api/v1 to match frontend expectations
    tags=["funding"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        429: {"description": "Too Many Requests"},
        500: {"description": "Internal Server Error"}
    }
)

# Initialize services
funding_controller = FundingController()


async def get_jwt_service() -> JWTService:
    """Get JWT service with dependencies."""
    redis_client = await get_redis()
    return JWTService(redis_client)


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token for protected endpoints."""
    try:
        jwt_service = await get_jwt_service()
        # JWTService expects TokenType enum
        from src.core.service.auth.models.token import TokenType
        payload = await jwt_service.verify_token(credentials.credentials, TokenType.ACCESS)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        return payload
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


@router.post(
    "/fund-address",
    response_model=FundingResponse,
    summary="Fund a derived address",
    description="Fund a derived address for Chain Signatures with native tokens",
    responses={
        401: {"description": "Authentication failed"},
        429: {"description": "Rate limit exceeded"}
    }
)
async def fund_address(
    request: FundingRequest,
    current_user: dict = Depends(verify_token)
) -> FundingResponse:
    """
    Fund a derived address for Chain Signatures.
    
    This endpoint funds a derived address with native tokens (ETH/BNB) on the specified chain.
    The funding amount is predetermined based on the chain configuration.
    
    Args:
        request: FundingRequest containing:
            - address: The derived address to fund
            - chain_id: The target chain ID (e.g., "97" for BSC Testnet)
    
    Returns:
        FundingResponse with transaction details including:
            - success: Whether the funding was successful
            - message: Status message
            - tx_hash: Transaction hash (if funded)
            - block_number: Block number (if funded)
            - funded: Whether new funding was sent
            - balance: Current balance (if already sufficient)
    """
    logger.info(f"Funding endpoint called for address: {request.address} by user: {current_user.wallet_address}")
    
    # Add user info to request context for rate limiting
    request_with_user = request.model_copy()
    setattr(request_with_user, '_user_wallet', current_user.wallet_address)
    
    return await funding_controller.fund_address(request_with_user)


@router.get(
    "/check-balance",
    response_model=BalanceResponse,
    summary="Check address balance",
    description="Check the balance of an address on a specific chain"
)
async def check_balance(
    address: str,
    chainId: str
) -> BalanceResponse:
    """
    Check address balance on specified chain.
    
    This endpoint retrieves the current balance of an address on the specified chain.
    
    Args:
        address: The address to check
        chainId: The chain ID
    
    Returns:
        BalanceResponse with:
            - success: Whether the check was successful
            - address: The checked address
            - chain_id: The chain ID
            - balance: Current balance in ETH/BNB
            - network: Network name
    """
    logger.info(f"Balance check endpoint called for address: {address}")
    return await funding_controller.check_balance(address=address, chain_id=chainId)


@router.get(
    "/funding-status",
    response_model=FundingStatus,
    summary="Get funding service status",
    description="Get the status and statistics of the funding service"
)
async def get_funding_status() -> FundingStatus:
    """
    Get funding service status and statistics.
    
    This endpoint provides information about the funding service configuration
    and the funder wallet balances across all supported networks.
    
    Returns:
        FundingStatus with:
            - configured: Whether the service is configured
            - message: Status message (if not configured)
            - funder_address: The funder wallet address (if configured)
            - balances: Balance information for each supported network
    """
    logger.info("Funding status endpoint called")
    return await funding_controller.get_funding_status()

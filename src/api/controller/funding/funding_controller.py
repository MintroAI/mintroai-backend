"""Funding controller for Chain Signatures."""

from typing import Optional
from fastapi import HTTPException, Query

from src.core.service.funding.funding_service import FundingService
from src.core.service.funding.models import (
    FundingRequest,
    BalanceCheckRequest,
    FundingStatus
)
from src.core.service.funding.models import FundingResponse, BalanceResponse
from src.core.service.funding.rate_limiter import FundingRateLimiter
from src.core.logger.logger import logger


class FundingController:
    """Controller for funding operations."""
    
    def __init__(self):
        """Initialize funding controller."""
        self.funding_service = FundingService()
        self.rate_limiter = FundingRateLimiter()
    
    async def fund_address(self, request: FundingRequest) -> FundingResponse:
        """
        Fund a derived address for Chain Signatures.
        
        Args:
            request: Funding request with address and chain_id
            
        Returns:
            FundingResponse with transaction details
            
        Raises:
            HTTPException: If funding fails
        """
        try:
            logger.info(f"Funding request for address: {request.address} on chain: {request.chain_id}")
            
            # Check rate limit if user wallet is available
            user_wallet = getattr(request, '_user_wallet', None)
            if user_wallet:
                rate_limit_check = await self.rate_limiter.check_rate_limit(user_wallet)
                if not rate_limit_check['allowed']:
                    raise HTTPException(
                        status_code=429,
                        detail=rate_limit_check
                    )
            
            # Validate request
            if not request.address or not request.chain_id:
                raise HTTPException(
                    status_code=400,
                    detail="Missing required parameters: address and chain_id"
                )
            
            # Process funding
            response = await self.funding_service.fund_address(request)
            
            # If funding was successful, increment rate limit counter
            if response.success and response.funded and user_wallet:
                await self.rate_limiter.increment_count(user_wallet)
            
            if not response.success:
                # Return appropriate status code based on error
                if "not configured" in response.message:
                    raise HTTPException(status_code=500, detail=response.message)
                elif "Unsupported chain" in response.message:
                    raise HTTPException(status_code=400, detail=response.message)
                elif "Invalid" in response.message:
                    raise HTTPException(status_code=400, detail=response.message)
                else:
                    raise HTTPException(status_code=500, detail=response.message)
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error in fund_address: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Internal server error: {str(e)}"
            )
    
    async def check_balance(
        self,
        address: Optional[str] = Query(None, description="The address to check"),
        chain_id: Optional[str] = Query(None, alias="chainId", description="The chain ID")
    ) -> BalanceResponse:
        """
        Check address balance on specified chain.
        
        Args:
            address: Address to check
            chain_id: Chain ID
            
        Returns:
            BalanceResponse with balance information
            
        Raises:
            HTTPException: If balance check fails
        """
        try:
            # Validate parameters
            if not address or not chain_id:
                raise HTTPException(
                    status_code=400,
                    detail="Missing required parameters: address and chainId"
                )
            
            logger.info(f"Balance check for address: {address} on chain: {chain_id}")
            
            # Check balance
            response = await self.funding_service.check_balance(address, chain_id)
            return response
            
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except ConnectionError as e:
            raise HTTPException(status_code=500, detail=str(e))
        except Exception as e:
            logger.error(f"Unexpected error in check_balance: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to check balance: {str(e)}"
            )
    
    async def get_funding_status(self) -> FundingStatus:
        """
        Get funding service status and statistics.
        
        Returns:
            FundingStatus with service information
            
        Raises:
            HTTPException: If status check fails
        """
        try:
            logger.info("Getting funding service status")
            
            # Get status
            status = await self.funding_service.get_funding_status()
            return status
            
        except Exception as e:
            logger.error(f"Unexpected error in get_funding_status: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to check funding status: {str(e)}"
            )

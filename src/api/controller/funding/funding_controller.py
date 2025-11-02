"""Funding controller for Chain Signatures."""

from typing import Optional
from fastapi import HTTPException, Query
from redis.asyncio import Redis

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
    
    def __init__(self, redis_client: Redis, funding_activity_repository=None):
        """Initialize funding controller with Redis and activity repository dependencies."""
        self.funding_service = FundingService()
        self.rate_limiter = FundingRateLimiter(redis_client)
        self.activity_repository = funding_activity_repository
    
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
        user_wallet = getattr(request, '_user_wallet', None)
        success = False
        
        try:
            logger.info(f"Funding request for address: {request.address} on chain: {request.chain_id}")
            
            # Check rate limit if user wallet is available
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
            
            success = response.success and response.funded
            
            # If funding was successful, increment rate limit counter
            if success and user_wallet:
                await self.rate_limiter.increment_count(user_wallet)
            
            # Log to database (non-blocking)
            if self.activity_repository and user_wallet:
                try:
                    await self.activity_repository.log_activity(
                        wallet_address=user_wallet,
                        funded_address=request.address,
                        chain_id=request.chain_id,
                        success=success,
                        amount=response.amount if success else None,
                        tx_hash=response.transactionHash if success else None
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log funding activity: {log_error}")
            
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
            # Log failure
            if self.activity_repository and user_wallet:
                try:
                    await self.activity_repository.log_activity(
                        wallet_address=user_wallet,
                        funded_address=request.address,
                        chain_id=request.chain_id,
                        success=False
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log funding failure: {log_error}")
            raise
        except Exception as e:
            # Log failure
            if self.activity_repository and user_wallet:
                try:
                    await self.activity_repository.log_activity(
                        wallet_address=user_wallet,
                        funded_address=request.address,
                        chain_id=request.chain_id,
                        success=False
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log funding failure: {log_error}")
            
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
            logger.info(f"Balance check for address: {address} on chain: {chain_id}")
            
            if not address or not chain_id:
                raise HTTPException(
                    status_code=400,
                    detail="Missing required parameters: address and chain_id"
                )
            
            check_request = BalanceCheckRequest(address=address, chain_id=chain_id)
            response = await self.funding_service.check_balance(check_request)
            
            if not response.success:
                raise HTTPException(status_code=400, detail="Failed to check balance")
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error in check_balance: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Internal server error: {str(e)}"
            )
    
    async def get_funding_status(self) -> FundingStatus:
        """
        Get funding service status and statistics.
        
        Returns:
            FundingStatus with service configuration and balances
            
        Raises:
            HTTPException: If status check fails
        """
        try:
            logger.info("Getting funding service status")
            return await self.funding_service.get_status()
        except Exception as e:
            logger.error(f"Unexpected error in get_funding_status: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Internal server error: {str(e)}"
            )

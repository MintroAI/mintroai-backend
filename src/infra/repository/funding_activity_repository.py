"""
Funding activity repository using SQLAlchemy ORM
"""

from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from src.infra.models import FundingActivityModel
from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class FundingActivityRepository:
    """Repository for funding activity logging"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def log_activity(
        self,
        wallet_address: str,
        funded_address: str,
        chain_id: str,
        success: bool,
        amount: Optional[str] = None,
        tx_hash: Optional[str] = None
    ) -> bool:
        """
        Log funding activity
        
        Args:
            wallet_address: User wallet address requesting funding
            funded_address: Address that received funds
            chain_id: Target chain ID
            success: Whether funding was successful
            amount: Amount funded (as string)
            tx_hash: Transaction hash
            
        Returns:
            True if successful, False otherwise
        """
        try:
            activity = FundingActivityModel(
                wallet_address=wallet_address.lower(),
                funded_address=funded_address.lower(),
                chain_id=chain_id,
                amount=amount,
                tx_hash=tx_hash,
                success=success
            )
            
            self.session.add(activity)
            await self.session.commit()
            
            logger.info(
                "Funding activity logged",
                extra={
                    "wallet_address": wallet_address,
                    "funded_address": funded_address,
                    "chain_id": chain_id,
                    "success": success,
                    "amount": amount
                }
            )
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to log funding activity",
                extra={
                    "wallet_address": wallet_address,
                    "funded_address": funded_address,
                    "chain_id": chain_id,
                    "error": str(e)
                }
            )
            return False


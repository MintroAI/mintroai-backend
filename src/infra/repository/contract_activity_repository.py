"""
Contract activity repository using SQLAlchemy ORM
"""

from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from src.infra.models import ContractActivityModel
from src.core.logger.logger import get_logger

logger = get_logger(__name__)


class ContractActivityRepository:
    """Repository for contract activity logging"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def log_activity(
        self,
        wallet_address: str,
        activity_type: str,
        success: bool,
        contract_type: Optional[str] = None,
        chat_id: Optional[str] = None,
        chain_id: Optional[str] = None
    ) -> bool:
        """
        Log contract activity
        
        Args:
            wallet_address: User wallet address
            activity_type: Type of activity ('generate', 'compile', 'get_price')
            success: Whether operation was successful
            contract_type: Contract type ('token', 'vesting')
            chat_id: Chat ID if available
            chain_id: Target chain ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            activity = ContractActivityModel(
                wallet_address=wallet_address.lower(),
                activity_type=activity_type,
                contract_type=contract_type,
                chat_id=chat_id,
                chain_id=chain_id,
                success=success
            )
            
            self.session.add(activity)
            await self.session.commit()
            
            logger.info(
                "Contract activity logged",
                extra={
                    "wallet_address": wallet_address,
                    "activity_type": activity_type,
                    "contract_type": contract_type,
                    "success": success
                }
            )
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to log contract activity",
                extra={
                    "wallet_address": wallet_address,
                    "activity_type": activity_type,
                    "error": str(e)
                }
            )
            return False


"""Contract generation controller"""

import logging
from typing import Union
from fastapi import HTTPException

from src.core.service.contract.contract_service import ContractService
from src.core.service.contract.models import (
    TokenContractData,
    VestingContractData,
    ContractData,
    ContractGenerationResponse
)


logger = logging.getLogger(__name__)


class ContractController:
    """Controller for smart contract generation endpoints"""
    
    def __init__(self):
        self.contract_service = ContractService()
    
    async def generate_contract(
        self,
        contract_data: Union[TokenContractData, VestingContractData],
        current_user: dict
    ) -> ContractGenerationResponse:
        """
        Generate smart contract based on provided configuration
        
        Args:
            contract_data: Contract configuration (Token or Vesting)
            current_user: Authenticated user data from JWT
            
        Returns:
            Generated contract code and metadata
            
        Raises:
            HTTPException: If generation fails or validation errors occur
        """
        try:
            # Extract wallet address from token payload
            user_data = {
                'wallet_address': getattr(current_user, 'wallet_address', None)
            }
            
            logger.info(
                f"Contract generation request from user: {user_data.get('wallet_address')}, "
                f"type: {contract_data.contractType}"
            )
            
            # Generate contract using service
            result = await self.contract_service.generate_contract(
                contract_data=contract_data,
                user_data=user_data
            )
            
            logger.info(
                f"Contract generated successfully for user: {user_data.get('wallet_address')}"
            )
            
            return result
            
        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise
        except Exception as e:
            logger.error(f"Unexpected error in contract generation: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Contract generation failed: {str(e)}"
            )

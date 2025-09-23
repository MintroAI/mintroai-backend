"""Contract generation controller"""

import logging
from typing import Union
from fastapi import HTTPException

from src.core.service.contract.contract_service import ContractService
from src.core.service.contract.models import (
    TokenContractData,
    VestingContractData,
    ContractData,
    ContractGenerationResponse,
    PriceContractRequest,
    PriceContractResponse
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
            
            # Generate contract using service
            result = await self.contract_service.generate_contract(
                contract_data=contract_data,
                user_data=user_data
            )
            
            # Normalize response for frontend
            if hasattr(result, 'contract') and result.contract:
                result.contractCode = result.contract
            
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
    
    async def compile_contract(
        self,
        chat_id: str,
        current_user: dict
    ) -> dict:
        """
        Compile smart contract by chat ID
        
        Args:
            chat_id: Chat ID from contract generation
            current_user: Authenticated user data from JWT
            
        Returns:
            Compilation result with bytecode and ABI
            
        Raises:
            HTTPException: If compilation fails
        """
        try:
            # Extract wallet address from token payload
            user_data = {
                'wallet_address': getattr(current_user, 'wallet_address', None)
            }
            
            # Compile contract using service
            result = await self.contract_service.compile_contract(
                chat_id=chat_id,
                user_data=user_data
            )
            
            return result
            
        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise
        except Exception as e:
            logger.error(f"Unexpected error in contract compilation: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Contract compilation failed: {str(e)}"
            )
    
    async def get_price(
        self,
        price_request: PriceContractRequest,
        current_user: dict
    ) -> PriceContractResponse:
        """
        Get contract deployment price and signature
        
        Args:
            price_request: Price request data with contractData and bytecode
            current_user: Authenticated user data from JWT
            
        Returns:
            Price and signature data for contract deployment
            
        Raises:
            HTTPException: If price calculation fails
        """
        try:
            # Extract wallet address from token payload
            user_data = {
                'wallet_address': getattr(current_user, 'wallet_address', None)
            }
            
            # Get price using service
            result = await self.contract_service.get_price(
                price_request=price_request,
                user_data=user_data
            )
            
            return result
            
        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise
        except Exception as e:
            logger.error(f"Unexpected error in contract pricing: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Contract pricing failed: {str(e)}"
            )

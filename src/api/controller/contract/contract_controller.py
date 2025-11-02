"""Contract generation controller"""

import logging
from typing import Union, Optional
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
    
    def __init__(self, contract_activity_repository=None):
        self.contract_service = ContractService()
        self.activity_repository = contract_activity_repository
    
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
        wallet_address = getattr(current_user, 'wallet_address', None)
        success = False
        
        try:
            # Extract wallet address from token payload
            user_data = {
                'wallet_address': wallet_address
            }
            
            # Generate contract using service
            result = await self.contract_service.generate_contract(
                contract_data=contract_data,
                user_data=user_data
            )
            
            # Normalize response for frontend
            if hasattr(result, 'contract') and result.contract:
                result.contractCode = result.contract
            
            success = getattr(result, 'success', True)
            
            # Log to database (non-blocking)
            if self.activity_repository and wallet_address:
                try:
                    await self.activity_repository.log_activity(
                        wallet_address=wallet_address,
                        activity_type='generate',
                        success=success,
                        contract_type=contract_data.contractType,
                        chat_id=getattr(contract_data, 'chatId', None),
                        chain_id=getattr(contract_data, 'chainId', None)
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log contract generation: {log_error}")
            
            return result
            
        except HTTPException:
            # Log failure
            if self.activity_repository and wallet_address:
                try:
                    await self.activity_repository.log_activity(
                        wallet_address=wallet_address,
                        activity_type='generate',
                        success=False,
                        contract_type=contract_data.contractType,
                        chat_id=getattr(contract_data, 'chatId', None),
                        chain_id=getattr(contract_data, 'chainId', None)
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log contract generation failure: {log_error}")
            raise
        except Exception as e:
            # Log failure
            if self.activity_repository and wallet_address:
                try:
                    await self.activity_repository.log_activity(
                        wallet_address=wallet_address,
                        activity_type='generate',
                        success=False,
                        contract_type=contract_data.contractType,
                        chat_id=getattr(contract_data, 'chatId', None),
                        chain_id=getattr(contract_data, 'chainId', None)
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log contract generation failure: {log_error}")
            
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
        wallet_address = getattr(current_user, 'wallet_address', None)
        
        try:
            # Extract wallet address from token payload
            user_data = {
                'wallet_address': wallet_address
            }
            
            # Compile contract using service
            result = await self.contract_service.compile_contract(
                chat_id=chat_id,
                user_data=user_data
            )
            
            success = result.get('success', True)
            
            # Log to database (non-blocking)
            if self.activity_repository and wallet_address:
                try:
                    await self.activity_repository.log_activity(
                        wallet_address=wallet_address,
                        activity_type='compile',
                        success=success,
                        chat_id=chat_id
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log contract compilation: {log_error}")
            
            return result
            
        except HTTPException:
            # Log failure
            if self.activity_repository and wallet_address:
                try:
                    await self.activity_repository.log_activity(
                        wallet_address=wallet_address,
                        activity_type='compile',
                        success=False,
                        chat_id=chat_id
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log contract compilation failure: {log_error}")
            raise
        except Exception as e:
            # Log failure
            if self.activity_repository and wallet_address:
                try:
                    await self.activity_repository.log_activity(
                        wallet_address=wallet_address,
                        activity_type='compile',
                        success=False,
                        chat_id=chat_id
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log contract compilation failure: {log_error}")
            
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
        wallet_address = getattr(current_user, 'wallet_address', None)
        
        try:
            # Extract wallet address from token payload
            user_data = {
                'wallet_address': wallet_address
            }
            
            # Get price using service
            result = await self.contract_service.get_price(
                price_request=price_request,
                user_data=user_data
            )
            
            success = getattr(result, 'success', True)
            chain_id = price_request.contractData.get('chainId') if isinstance(price_request.contractData, dict) else None
            
            # Log to database (non-blocking)
            if self.activity_repository and wallet_address:
                try:
                    await self.activity_repository.log_activity(
                        wallet_address=wallet_address,
                        activity_type='get_price',
                        success=success,
                        chain_id=chain_id
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log price check: {log_error}")
            
            return result
            
        except HTTPException:
            # Log failure
            if self.activity_repository and wallet_address:
                try:
                    chain_id = price_request.contractData.get('chainId') if isinstance(price_request.contractData, dict) else None
                    await self.activity_repository.log_activity(
                        wallet_address=wallet_address,
                        activity_type='get_price',
                        success=False,
                        chain_id=chain_id
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log price check failure: {log_error}")
            raise
        except Exception as e:
            # Log failure
            if self.activity_repository and wallet_address:
                try:
                    chain_id = price_request.contractData.get('chainId') if isinstance(price_request.contractData, dict) else None
                    await self.activity_repository.log_activity(
                        wallet_address=wallet_address,
                        activity_type='get_price',
                        success=False,
                        chain_id=chain_id
                    )
                except Exception as log_error:
                    logger.error(f"Failed to log price check failure: {log_error}")
            
            logger.error(f"Unexpected error in contract pricing: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Contract pricing failed: {str(e)}"
            )

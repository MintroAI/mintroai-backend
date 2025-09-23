"""Contract generation service"""

import os
import logging
import httpx
from typing import Dict, Any
from fastapi import HTTPException

from .models import (
    ContractData,
    TokenContractData,
    VestingContractData,
    ContractGenerationResponse,
    PriceContractRequest,
    PriceContractResponse
)


logger = logging.getLogger(__name__)


class ContractService:
    """Service for handling smart contract generation"""
    
    def __init__(self):
        self.contract_generator_url = os.getenv("CONTRACT_GENERATOR_URL")
        if not self.contract_generator_url:
            raise ValueError("CONTRACT_GENERATOR_URL environment variable is required")
        
        self.signature_service_url = os.getenv("SIGNATURE_SERVICE_URL")
        if not self.signature_service_url:
            raise ValueError("SIGNATURE_SERVICE_URL environment variable is required")
        
        # Configure HTTP timeout from environment or use default
        self.http_timeout = float(os.getenv("CONTRACT_HTTP_TIMEOUT", "30.0"))
    
    async def _make_http_request(
        self,
        method: str,
        url: str,
        json_data: Dict[str, Any] = None,
        service_name: str = "External service"
    ) -> Dict[str, Any]:
        """
        Make HTTP request to external service with common error handling
        
        Args:
            method: HTTP method (POST, GET, etc.)
            url: Full URL to make request to
            json_data: JSON payload for request
            service_name: Name of service for error messages
            
        Returns:
            JSON response from service
            
        Raises:
            HTTPException: If request fails
        """
        try:
            async with httpx.AsyncClient(timeout=self.http_timeout) as client:
                if method.upper() == "POST":
                    response = await client.post(
                        url,
                        json=json_data,
                        headers={"Content-Type": "application/json"}
                    )
                else:
                    response = await client.request(method, url)
                
                if response.status_code != 200:
                    logger.error(
                        f"{service_name} error: {response.status_code} - {response.text}"
                    )
                    raise HTTPException(
                        status_code=502,
                        detail=f"{service_name} temporarily unavailable"
                    )
                
                return response.json()
                
        except httpx.TimeoutException:
            logger.error(f"{service_name} timeout after {self.http_timeout}s")
            raise HTTPException(
                status_code=504,
                detail=f"{service_name} timeout"
            )
        except httpx.RequestError as e:
            logger.error(f"{service_name} connection error: {str(e)}")
            raise HTTPException(
                status_code=502,
                detail=f"{service_name} connection failed"
            )
        except Exception as e:
            logger.error(f"{service_name} unexpected error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"{service_name} request failed"
            )
    
    def _handle_service_error(self, error: Exception, operation: str) -> HTTPException:
        """
        Handle service-level errors with consistent logging and response
        
        Args:
            error: The exception that occurred
            operation: Description of the operation that failed
            
        Returns:
            HTTPException with appropriate status code and message
        """
        if isinstance(error, HTTPException):
            return error
        
        logger.error(f"{operation} error: {str(error)}")
        return HTTPException(
            status_code=500,
            detail=f"Failed to {operation.lower()}: {str(error)}"
        )
    
    async def generate_contract(
        self,
        contract_data: ContractData,
        user_data: Dict[str, Any]
    ) -> ContractGenerationResponse:
        """
        Generate smart contract based on provided data
        
        Args:
            contract_data: Contract configuration data
            user_data: Authenticated user data from JWT
            
        Returns:
            ContractGenerationResponse with generated contract code
        """
        try:
            # Call external contract generation service
            result = await self._make_http_request(
                method="POST",
                url=f"{self.contract_generator_url}/api/generate-contract",
                json_data=contract_data.dict(exclude_none=True),
                service_name="Contract generation service"
            )
            
            # Parse response and ensure contractCode is set
            response_obj = ContractGenerationResponse(**result)
            if not response_obj.contractCode and response_obj.contract:
                response_obj.contractCode = response_obj.contract
            return response_obj
                
        except Exception as e:
            raise self._handle_service_error(e, "generate contract")
    
    async def compile_contract(
        self,
        chat_id: str,
        user_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Compile smart contract by chat ID
        
        Args:
            chat_id: Chat ID from contract generation
            user_data: Authenticated user data from JWT
            
        Returns:
            Compilation result with bytecode and ABI
        """
        try:
            # Call external contract compilation service
            result = await self._make_http_request(
                method="POST",
                url=f"{self.contract_generator_url}/api/compile-contract/{chat_id}",
                service_name="Contract compilation service"
            )
            
            # Ensure success field is set
            if 'success' not in result:
                result['success'] = True
            
            return result
                
        except Exception as e:
            raise self._handle_service_error(e, "compile contract")
    
    async def get_price(
        self,
        price_request: PriceContractRequest,
        user_data: Dict[str, Any]
    ) -> PriceContractResponse:
        """
        Get contract deployment price and signature
        
        Args:
            price_request: Price request data with contractData and bytecode
            user_data: Authenticated user data from JWT
            
        Returns:
            PriceContractResponse with pricing and signature data
        """
        try:
            # Extract deployer address from request or contractData
            deployer_address = price_request.deployerAddress or price_request.contractData.get('ownerAddress')
            
            # Prepare request payload
            request_payload = {
                "contractData": price_request.contractData,
                "bytecode": price_request.bytecode,
                "deployerAddress": deployer_address,
                "deploymentType": price_request.deploymentType
            }
            
            # Call external signature service
            result = await self._make_http_request(
                method="POST",
                url=f"{self.signature_service_url}/api/signature/prepare",
                json_data=request_payload,
                service_name="Price calculation service"
            )
            
            # Ensure success field is set
            if 'success' not in result:
                result['success'] = True
            
            return PriceContractResponse(**result)
                
        except Exception as e:
            raise self._handle_service_error(e, "calculate contract price")
    

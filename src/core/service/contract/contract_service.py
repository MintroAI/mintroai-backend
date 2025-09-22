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
    ContractGenerationResponse
)


logger = logging.getLogger(__name__)


class ContractService:
    """Service for handling smart contract generation"""
    
    def __init__(self):
        self.contract_generator_url = os.getenv("CONTRACT_GENERATOR_URL")
        if not self.contract_generator_url:
            logger.warning("CONTRACT_GENERATOR_URL not configured, will use mock responses")
    
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
            # 1. Check if we should use mock response
            if not self.contract_generator_url:
                return await self._generate_mock_contract(contract_data)
            
            # 2. Call external contract generation service
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.contract_generator_url}/api/generate-contract",
                    json=contract_data.dict(exclude_none=True),
                    headers={
                        "Content-Type": "application/json",
                    }
                )
                
                if response.status_code != 200:
                    logger.error(
                        f"External service error: {response.status_code} - {response.text}"
                    )
                    raise HTTPException(
                        status_code=502,
                        detail="Contract generation service temporarily unavailable"
                    )
                
                result = response.json()
                
                # Parse response and ensure contractCode is set
                response_obj = ContractGenerationResponse(**result)
                if not response_obj.contractCode and response_obj.contract:
                    response_obj.contractCode = response_obj.contract
                return response_obj
                
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Contract generation error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to generate contract: {str(e)}"
            )
    
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
            # Check if we should use mock response
            if not self.contract_generator_url:
                return {
                    "success": True,
                    "bytecode": "0x608060405234801561001057600080fd5b50...",
                    "abi": [
                        {
                            "inputs": [],
                            "name": "name",
                            "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                            "stateMutability": "view",
                            "type": "function"
                        }
                    ],
                    "message": "Mock contract compiled successfully"
                }
            
            # Call external contract compilation service
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.contract_generator_url}/api/compile-contract/{chat_id}",
                    headers={
                        "Content-Type": "application/json",
                    }
                )
                
                if response.status_code != 200:
                    logger.error(
                        f"External service error: {response.status_code} - {response.text}"
                    )
                    raise HTTPException(
                        status_code=502,
                        detail="Contract compilation service temporarily unavailable"
                    )
                
                result = response.json()
                
                # Ensure success field is set
                if 'success' not in result:
                    result['success'] = True
                
                return result
                
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Contract compilation error: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to compile contract: {str(e)}"
            )
    
    async def _generate_mock_contract(
        self,
        contract_data: ContractData
    ) -> ContractGenerationResponse:
        """
        Generate mock contract for development/testing
        
        Args:
            contract_data: Contract configuration
            
        Returns:
            Mock contract generation response
        """
        if isinstance(contract_data, TokenContractData):
            contract_name = contract_data.tokenName or "MockToken"
            contract_symbol = contract_data.tokenSymbol or "MOCK"
            initial_supply = contract_data.initialSupply or "1000000"
            decimals = contract_data.decimals or 18
            
            mock_code = f"""// Mock ERC20 Token Contract for {contract_name}
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract {contract_name.replace(' ', '').replace('-', '')} is ERC20, Ownable {{
    constructor() ERC20("{contract_name}", "{contract_symbol}") {{
        _mint(msg.sender, {initial_supply} * 10**{decimals});
    }}
    
    {'function mint(address to, uint256 amount) public onlyOwner { _mint(to, amount); }' if contract_data.mintable else ''}
    {'function burn(uint256 amount) public { _burn(msg.sender, amount); }' if contract_data.burnable else ''}
}}"""
        else:  # VestingContractData
            mock_code = f"""// Mock Vesting Contract
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract VestingContract is Ownable {{
    IERC20 public token;
    uint256 public tgeTimestamp = {contract_data.tgeTimestamp or 0};
    uint256 public tgeRate = {contract_data.tgeRate or 10};
    uint256 public cliff = {contract_data.cliff or 30};
    uint256 public releaseRate = {contract_data.releaseRate or 10};
    
    constructor(address _token) {{
        token = IERC20(_token);
    }}
}}"""
        
        return ContractGenerationResponse(
            success=True,
            contractCode=mock_code,
            message="Mock contract generated successfully"
        )

"""Contract generation models"""

from typing import Literal, List, Optional, Union
from pydantic import BaseModel, Field, field_validator


class TokenContractData(BaseModel):
    """Token contract generation data model"""
    contractType: Literal['token']
    chatId: Optional[str] = None
    contractName: Optional[str] = None
    tokenName: Optional[str] = None
    tokenSymbol: Optional[str] = None
    decimals: Optional[int] = 18
    initialSupply: Optional[str] = None
    ownerAddress: Optional[str] = None
    chainId: Optional[str] = None
    isChainSignatures: Optional[bool] = False
    mintable: Optional[bool] = False
    burnable: Optional[bool] = False
    pausable: Optional[bool] = False
    blacklist: Optional[bool] = False
    maxTx: Optional[bool] = False
    maxTxAmount: Optional[int] = 0
    transferTax: Optional[int] = 0
    antiBot: Optional[bool] = False
    cooldownTime: Optional[int] = 0

    @field_validator('decimals')
    @classmethod
    def validate_decimals(cls, v):
        if v is not None and (v < 0 or v > 18):
            raise ValueError('Decimals must be between 0 and 18')
        return v

    @field_validator('transferTax')
    @classmethod
    def validate_transfer_tax(cls, v):
        if v is not None and (v < 0 or v > 100):
            raise ValueError('Transfer tax must be between 0 and 100')
        return v


class VestingContractData(BaseModel):
    """Vesting contract generation data model"""
    contractType: Literal['vesting']
    chatId: Optional[str] = None
    contractName: Optional[str] = None
    tokenAddress: Optional[str] = None
    tgeTimestamp: Optional[int] = None
    tgeRate: Optional[int] = None
    cliff: Optional[int] = None
    releaseRate: Optional[int] = None
    period: Optional[int] = None
    vestingSupply: Optional[int] = None
    decimals: Optional[int] = 18
    ownerAddress: Optional[str] = None
    chainId: Optional[str] = None
    users: Optional[List[str]] = Field(default_factory=list)
    amts: Optional[List[int]] = Field(default_factory=list)

    @field_validator('amts')
    @classmethod
    def validate_amounts(cls, v, info):
        if 'users' in info.data:
            users = info.data['users']
            if users and v and len(users) != len(v):
                raise ValueError('Users and amounts arrays must have the same length')
        return v

    @field_validator('tgeRate', 'releaseRate')
    @classmethod
    def validate_rates(cls, v):
        if v is not None and (v < 0 or v > 100):
            raise ValueError('Rate must be between 0 and 100')
        return v


# Union type for contract data
ContractData = Union[TokenContractData, VestingContractData]


class ContractGenerationResponse(BaseModel):
    """Response model for contract generation"""
    success: Optional[bool] = True
    contractCode: Optional[str] = None
    contract: Optional[str] = None  # External service uses 'contract' field
    message: Optional[str] = None
    error: Optional[str] = None
    transactionHash: Optional[str] = None
    contractAddress: Optional[str] = None
    parameters: Optional[dict] = None
    files: Optional[dict] = None
    
    @property
    def code(self) -> Optional[str]:
        """Get contract code from either contractCode or contract field"""
        return self.contractCode or self.contract


class CompileContractRequest(BaseModel):
    """Request model for contract compilation"""
    chatId: str


class CompileContractResponse(BaseModel):
    """Response model for contract compilation"""
    success: Optional[bool] = True
    bytecode: Optional[str] = None
    abi: Optional[list] = None
    message: Optional[str] = None
    error: Optional[str] = None
    compiler: Optional[dict] = None
    metadata: Optional[dict] = None
    contractInfo: Optional[dict] = None
    warnings: Optional[list] = None


class PriceContractRequest(BaseModel):
    """Request model for contract pricing"""
    contractData: dict  # Contains contract metadata (ownerAddress, chainId, etc.)
    bytecode: str
    deployerAddress: Optional[str] = None  # If not provided, will use contractData.ownerAddress
    deploymentType: Optional[str] = "create"  # Default deployment type

    @field_validator('bytecode')
    @classmethod
    def validate_bytecode(cls, v):
        """Ensure bytecode is properly formatted"""
        if not v:
            raise ValueError('Bytecode is required')
        # Ensure it starts with 0x
        if not v.startswith('0x'):
            v = f'0x{v}'
        return v

    @field_validator('contractData')
    @classmethod
    def validate_contract_data(cls, v):
        """Validate required fields in contractData"""
        if not isinstance(v, dict):
            raise ValueError('contractData must be a dictionary')
        
        if not v.get('ownerAddress'):
            raise ValueError('ownerAddress is required in contractData')
        
        if not v.get('chainId'):
            raise ValueError('chainId is required in contractData')
        
        return v


class PriceContractResponse(BaseModel):
    """Response model for contract pricing"""
    success: Optional[bool] = True
    data: Optional[dict] = None  # Contains signature, deploymentData, pricing, etc.
    message: Optional[str] = None
    error: Optional[str] = None

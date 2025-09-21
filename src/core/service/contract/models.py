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
    success: bool
    contractCode: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
    transactionHash: Optional[str] = None
    contractAddress: Optional[str] = None

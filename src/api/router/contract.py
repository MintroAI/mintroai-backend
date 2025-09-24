"""Contract generation router"""

from typing import Union
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from src.api.controller.contract.contract_controller import ContractController
from src.core.service.contract.models import (
    TokenContractData,
    VestingContractData,
    ContractGenerationResponse,
    CompileContractRequest,
    CompileContractResponse,
    PriceContractRequest,
    PriceContractResponse
)
from src.core.service.auth.models.token import TokenType
from src.core.logger.logger import logger
from src.core.dependencies import get_jwt_service


# Security scheme
security = HTTPBearer()

# Create router with prefix and tags
router = APIRouter(
    prefix="/api/v1",
    tags=["Smart Contracts"],
    responses={
        401: {"description": "Unauthorized"},
        502: {"description": "Bad Gateway"}
    }
)

# JWT service dependency moved to src.core.dependencies


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    jwt_service = Depends(get_jwt_service)
):
    """Verify JWT token - required for this endpoint."""
    try:
        payload = await jwt_service.verify_token(credentials.credentials, TokenType.ACCESS)
        return payload
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )


@router.post(
    "/generate-contract",
    response_model=ContractGenerationResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate Smart Contract",
    description="Generate a smart contract (Token or Vesting) with custom configuration. Requires JWT authentication."
)
async def generate_contract(
    contract_data: Union[TokenContractData, VestingContractData],
    current_user: dict = Depends(verify_token)
) -> ContractGenerationResponse:
    """
    Generate a smart contract with the provided configuration.
    
    This endpoint requires JWT authentication.
    
    Args:
        contract_data: Contract configuration (Token or Vesting type)
        current_user: Authenticated user from JWT
        
    Returns:
        ContractGenerationResponse with generated contract code
    """
    controller = ContractController()
    return await controller.generate_contract(
        contract_data=contract_data,
        current_user=current_user
    )


@router.post(
    "/compile-contract", 
    response_model=CompileContractResponse,
    status_code=status.HTTP_200_OK,
    summary="Compile Smart Contract",
    description="Compile a generated smart contract to bytecode and ABI using chat ID. Requires JWT authentication."
)
async def compile_contract(
    request: dict,  # Geçici olarak dict yapalım
    current_user: dict = Depends(verify_token)
) -> CompileContractResponse:
    """
    Compile a smart contract that was previously generated.
    
    This endpoint requires JWT authentication.
    
    Args:
        request: Compilation request with chatId
        current_user: Authenticated user from JWT
        
    Returns:
        CompileContractResponse with bytecode and ABI
    """
    logger.info(f"Compile request data: {request}")
    chat_id = request.get('chatId') or request.get('chat_id')
    if not chat_id:
        raise HTTPException(status_code=400, detail="chatId field is required")
    
    controller = ContractController()
    return await controller.compile_contract(
        chat_id=chat_id,
        current_user=current_user
    )


@router.post(
    "/price-contract",
    response_model=PriceContractResponse, 
    status_code=status.HTTP_200_OK,
    summary="Get Contract Price",
    description="Calculate deployment cost and generate signature for contract deployment. Requires JWT authentication."
)
async def get_contract_price(
    price_request: PriceContractRequest,
    current_user: dict = Depends(verify_token)
) -> PriceContractResponse:
    """
    Get deployment price and signature for a smart contract.
    
    This endpoint requires JWT authentication and calculates the cost
    and generates signature data needed for contract deployment.
    
    Args:
        price_request: Request containing contractData and bytecode
        current_user: Authenticated user from JWT
        
    Returns:
        PriceContractResponse with pricing and signature data
    """
    controller = ContractController()
    return await controller.get_price(
        price_request=price_request,
        current_user=current_user
    )

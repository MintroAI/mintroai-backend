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
from src.core.service.auth.jwt_service import JWTService
from src.core.service.auth.models.token import TokenType
from src.infra.config.redis import get_redis
from src.core.logger.logger import logger


# Security scheme
security = HTTPBearer()

# Create router with prefix and tags
router = APIRouter(
    prefix="/api/v1",
    tags=["Contract"],
    responses={
        401: {"description": "Unauthorized"},
        502: {"description": "Bad Gateway - External Service Error"}
    }
)

async def get_contract_controller() -> ContractController:
    """Get contract controller instance."""
    return ContractController()


async def get_jwt_service() -> JWTService:
    """Get JWT service with dependencies."""
    redis_client = await get_redis()
    return JWTService(redis_client)


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token - required for this endpoint."""
    try:
        jwt_service = await get_jwt_service()
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
    description="Generate a smart contract (Token or Vesting) based on provided configuration"
)
async def generate_contract(
    contract_data: Union[TokenContractData, VestingContractData],
    current_user: dict = Depends(verify_token),
    controller: ContractController = Depends(get_contract_controller)
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
    return await controller.generate_contract(
        contract_data=contract_data,
        current_user=current_user
    )


@router.post(
    "/compile-contract",
    response_model=CompileContractResponse,
    status_code=status.HTTP_200_OK,
    summary="Compile Smart Contract",
    description="Compile a generated smart contract using chat ID"
)
async def compile_contract(
    request: dict,  # Geçici olarak dict yapalım
    current_user: dict = Depends(verify_token),
    controller: ContractController = Depends(get_contract_controller)
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
    
    return await controller.compile_contract(
        chat_id=chat_id,
        current_user=current_user
    )


@router.post(
    "/price-contract",
    response_model=PriceContractResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Contract Price",
    description="Get deployment price and signature for a smart contract",
    responses={
        400: {"description": "Bad Request - Invalid input data"},
        401: {"description": "Unauthorized"},
        502: {"description": "Bad Gateway - External Service Error"}
    }
)
async def get_contract_price(
    price_request: PriceContractRequest,
    current_user: dict = Depends(verify_token),
    controller: ContractController = Depends(get_contract_controller)
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
    return await controller.get_price(
        price_request=price_request,
        current_user=current_user
    )

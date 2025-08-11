"""
Authentication API endpoints for multi-protocol wallet authentication.
Supports EVM (Ethereum) and NEAR Protocol wallets.
"""

from fastapi import APIRouter, HTTPException, status, Depends
from typing import Dict, Any

from src.core.service.auth.models.challenge import ChallengeRequest, ChallengeResponse
from src.core.service.auth.models.auth import VerifyRequest, AuthResponse, RefreshTokenRequest, LogoutRequest
from src.core.service.auth.challenge_service import ChallengeService
from src.core.service.auth.jwt_service import JWTService
from src.core.service.auth.multi_protocol_signature_service import MultiProtocolSignatureService
from src.core.service.auth.protocols.base import BlockchainProtocol, protocol_registry
from src.core.service.auth.protocols.evm import create_evm_verifier
from src.core.service.auth.protocols.near import create_near_verifier
from src.core.service.auth.cache.challenge_store import ChallengeStore
from src.core.service.auth.cache.token_store import TokenStore
from src.infra.config.redis import get_redis
from src.infra.config.settings import get_settings
from src.core.logger.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()
router = APIRouter(prefix="/auth", tags=["Authentication"])


# Initialize protocol verifiers (temporary until we have proper startup)
async def init_protocols():
    """Initialize protocol verifiers"""
    try:
        # Register EVM verifier
        evm_verifier = create_evm_verifier("mainnet", chain_id=1)
        await evm_verifier.initialize()
        protocol_registry.register(evm_verifier)
        
        # Register NEAR verifier if enabled
        if settings.NEAR_ENABLED:
            try:
                near_verifier = create_near_verifier(
                    network_id=settings.NEAR_NETWORK_ID,
                    rpc_urls=settings.NEAR_RPC_URLS
                )
                await near_verifier.initialize()
                protocol_registry.register(near_verifier)
                logger.info("NEAR verifier registered successfully")
            except Exception as near_error:
                logger.warning(f"NEAR verifier initialization failed, registering without RPC: {str(near_error)}")
                # Register NEAR verifier without initialization for testing
                near_verifier = create_near_verifier(
                    network_id=settings.NEAR_NETWORK_ID,
                    rpc_urls=settings.NEAR_RPC_URLS
                )
                # Skip initialization but still register
                protocol_registry.register(near_verifier)
                logger.info("NEAR verifier registered in offline mode")
            
        logger.info("Protocol verifiers initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize protocol verifiers: {str(e)}")


# Dependency to ensure protocols are initialized
async def ensure_protocols_initialized():
    """Ensure protocol verifiers are initialized"""
    if len(protocol_registry.get_supported_protocols()) == 0:
        await init_protocols()


# Dependencies
async def get_challenge_service() -> ChallengeService:
    """Get challenge service instance"""
    await ensure_protocols_initialized()
    redis = await get_redis()
    challenge_store = ChallengeStore(redis)
    multi_signature_service = MultiProtocolSignatureService()
    return ChallengeService(challenge_store, multi_signature_service)


async def get_jwt_service() -> JWTService:
    """Get JWT service instance"""
    redis = await get_redis()
    token_store = TokenStore(redis)
    return JWTService(token_store)


@router.post("/challenge", response_model=ChallengeResponse)
async def create_challenge(
    request: ChallengeRequest,
    challenge_service: ChallengeService = Depends(get_challenge_service)
):
    """
    Create a new authentication challenge for a wallet address.
    
    The challenge must be signed by the wallet to prove ownership.
    """
    try:
        # Validate protocol
        try:
            protocol = BlockchainProtocol(request.protocol.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported protocol: {request.protocol}. Supported: {[p.value for p in BlockchainProtocol]}"
            )
        
        # Create challenge
        challenge = await challenge_service.create_challenge(
            wallet_address=request.wallet_address,
            protocol=protocol
        )
        
        # Calculate expires_in
        expires_in = int((challenge.expires_at - challenge.timestamp).total_seconds())
        
        return ChallengeResponse(
            nonce=challenge.nonce,
            message=challenge.message,
            expires_in=expires_in
        )
        
    except ValueError as e:
        logger.warning(f"Invalid challenge request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to create challenge: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create challenge"
        )


@router.post("/verify", response_model=AuthResponse)
async def verify_challenge(
    request: VerifyRequest,
    challenge_service: ChallengeService = Depends(get_challenge_service),
    jwt_service: JWTService = Depends(get_jwt_service)
):
    """
    Verify a signed challenge and return authentication tokens.
    
    For NEAR protocol, public_key parameter is optional but recommended for better performance.
    """
    try:
        # Validate protocol
        try:
            protocol = BlockchainProtocol(request.protocol.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported protocol: {request.protocol}. Supported: {[p.value for p in BlockchainProtocol]}"
            )
        
        # Prepare protocol-specific kwargs
        verify_kwargs = {}
        if protocol == BlockchainProtocol.NEAR and request.public_key:
            verify_kwargs['public_key'] = request.public_key
        
        # Verify challenge
        is_valid, error = await challenge_service.verify_challenge(
            wallet_address=request.wallet_address,
            signature=request.signature,
            protocol=protocol,
            **verify_kwargs
        )
        
        if not is_valid:
            logger.warning(
                f"Challenge verification failed for {request.wallet_address}",
                extra={
                    "protocol": protocol.value,
                    "error": error
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid signature: {error}"
            )
        
        # Generate tokens
        tokens = await jwt_service.create_tokens(request.wallet_address)
        
        logger.info(
            f"Authentication successful for {request.wallet_address}",
            extra={"protocol": protocol.value}
        )
        
        return AuthResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to verify challenge: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@router.post("/refresh", response_model=AuthResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    jwt_service: JWTService = Depends(get_jwt_service)
):
    """
    Refresh access token using a valid refresh token.
    """
    try:
        tokens = await jwt_service.refresh_tokens(request.refresh_token)
        
        return AuthResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to refresh token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@router.post("/logout")
async def logout(
    request: LogoutRequest,
    jwt_service: JWTService = Depends(get_jwt_service)
):
    """
    Logout and blacklist tokens.
    """
    try:
        if request.refresh_token:
            await jwt_service.blacklist_token(request.refresh_token)
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Failed to logout: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.get("/protocols")
async def get_supported_protocols() -> Dict[str, Any]:
    """
    Get list of supported blockchain protocols.
    """
    await ensure_protocols_initialized()
    
    protocols = protocol_registry.get_supported_protocols()
    
    return {
        "supported_protocols": [p.value for p in protocols],
        "default_protocol": "evm"
    }
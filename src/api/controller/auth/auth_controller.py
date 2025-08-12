"""
Authentication controller with enhanced error handling and validation.
"""

from fastapi import APIRouter, HTTPException, status, Depends
from typing import Dict, Any
from datetime import datetime

from src.api.controller.auth.dto.input_dto import (
    ChallengeRequestDto, VerifyRequestDto, RefreshTokenRequestDto, LogoutRequestDto
)
from src.api.controller.auth.dto.output_dto import (
    ChallengeResponseDto, AuthResponseDto, TokenRefreshResponseDto, 
    LogoutResponseDto, SessionStatusResponseDto, ProtocolsResponseDto, AccountInfoResponseDto
)
from src.api.controller.auth.dto.error_responses import ErrorCode, ErrorDetail, ErrorResponse
from src.api.utils.validators import RequestValidator, ValidationException, validation_exception_handler

from src.core.service.auth.challenge_service import ChallengeService
from src.core.service.auth.jwt_service import JWTService, TokenType
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


# Initialize protocol verifiers
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
                protocol_registry.register(near_verifier)
                logger.info("NEAR verifier registered in offline mode")
        
        logger.info(f"Initialized {len(protocol_registry.verifiers)} protocol verifiers")
        
    except Exception as e:
        logger.error(f"Failed to initialize protocol verifiers: {str(e)}")
        raise


# Dependency providers
async def get_challenge_service() -> ChallengeService:
    """Get challenge service with dependencies."""
    redis_client = await get_redis()
    challenge_store = ChallengeStore(redis_client)
    
    # Initialize multi-protocol signature service (no constructor args needed)
    multi_signature_service = MultiProtocolSignatureService()
    
    return ChallengeService(challenge_store, multi_signature_service)


async def get_jwt_service() -> JWTService:
    """Get JWT service with dependencies."""
    redis_client = await get_redis()
    token_store = TokenStore(redis_client)
    return JWTService(token_store)


@router.post("/challenge", response_model=ChallengeResponseDto)
async def create_challenge(
    request: ChallengeRequestDto,
    challenge_service: ChallengeService = Depends(get_challenge_service)
):
    """
    Create a new authentication challenge for a wallet address.
    
    The challenge must be signed by the wallet to prove ownership.
    Supports both EVM and NEAR protocols with protocol-specific validation.
    """
    try:
        # Enhanced validation using our validators
        protocol = RequestValidator.validate_protocol(request.protocol.value)
        wallet_address = RequestValidator.validate_wallet_address(request.wallet_address, protocol)
        
        # Create challenge
        challenge = await challenge_service.create_challenge(
            wallet_address=wallet_address,
            protocol=protocol
        )
        
        # Calculate expires_in
        expires_in = int((challenge.expires_at - challenge.timestamp).total_seconds())
        
        logger.info(
            f"Challenge created for {wallet_address}",
            extra={
                "protocol": protocol.value,
                "nonce": challenge.nonce,
                "expires_in": expires_in
            }
        )
        
        return ChallengeResponseDto(
            nonce=challenge.nonce,
            message=challenge.message,
            expires_in=expires_in,
            protocol=protocol.value
        )
        
    except ValidationException as e:
        logger.warning(f"Validation failed for challenge request: {e}")
        validation_exception_handler(request, e)
        
    except ValueError as e:
        logger.warning(f"Invalid challenge request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": {
                    "code": ErrorCode.INVALID_INPUT,
                    "message": str(e),
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to create challenge: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": ErrorCode.INTERNAL_ERROR,
                    "message": "Failed to create challenge",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }
        )


@router.post("/verify", response_model=AuthResponseDto)
async def verify_challenge(
    request: VerifyRequestDto,
    challenge_service: ChallengeService = Depends(get_challenge_service),
    jwt_service: JWTService = Depends(get_jwt_service)
):
    """
    Verify a signed challenge and return authentication tokens.
    
    For NEAR protocol, public_key parameter is optional but recommended for better performance.
    Returns JWT access and refresh tokens upon successful verification.
    """
    try:
        # Enhanced validation
        protocol = RequestValidator.validate_protocol(request.protocol.value)
        wallet_address = RequestValidator.validate_wallet_address(request.wallet_address, protocol)
        signature = RequestValidator.validate_signature(request.signature, protocol)
        public_key = RequestValidator.validate_public_key(request.public_key, protocol)
        
        # Prepare protocol-specific kwargs
        verify_kwargs = {}
        if protocol == BlockchainProtocol.NEAR and public_key:
            verify_kwargs['public_key'] = public_key
        
        # Verify challenge
        is_valid, error = await challenge_service.verify_challenge(
            wallet_address=wallet_address,
            signature=signature,
            protocol=protocol,
            **verify_kwargs
        )
        
        if not is_valid:
            logger.warning(
                f"Challenge verification failed for {wallet_address}",
                extra={
                    "protocol": protocol.value,
                    "error": error
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": {
                        "code": ErrorCode.INVALID_SIGNATURE,
                        "message": f"Invalid signature: {error}",
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                }
            )
        
        # Generate tokens
        tokens = await jwt_service.create_tokens(wallet_address)
        
        logger.info(
            f"Authentication successful for {wallet_address}",
            extra={"protocol": protocol.value}
        )
        
        return AuthResponseDto(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            wallet_address=wallet_address,
            protocol=protocol.value
        )
        
    except ValidationException as e:
        logger.warning(f"Validation failed for verify request: {e}")
        validation_exception_handler(request, e)
        
    except HTTPException:
        raise
        
    except Exception as e:
        logger.error(f"Failed to verify challenge: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": ErrorCode.INTERNAL_ERROR,
                    "message": "Authentication failed",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }
        )


@router.post("/refresh", response_model=TokenRefreshResponseDto)
async def refresh_token(
    request: RefreshTokenRequestDto,
    jwt_service: JWTService = Depends(get_jwt_service)
):
    """
    Refresh access token using a valid refresh token.
    
    The refresh token must be valid and not expired.
    Returns a new access token with the same expiration time.
    """
    try:
        # Validate refresh token format
        refresh_token = RequestValidator.validate_token(request.refresh_token, "refresh_token")
        
        # Refresh tokens
        tokens = await jwt_service.refresh_tokens(refresh_token)
        
        logger.info("Token refreshed successfully")
        
        return TokenRefreshResponseDto(
            access_token=tokens.access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except ValidationException as e:
        logger.warning(f"Validation failed for refresh request: {e}")
        validation_exception_handler(request, e)
        
    except HTTPException:
        raise
        
    except Exception as e:
        logger.error(f"Failed to refresh token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": ErrorCode.INVALID_TOKEN,
                    "message": "Invalid or expired refresh token",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }
        )


@router.post("/logout", response_model=LogoutResponseDto)
async def logout(
    request: LogoutRequestDto,
    jwt_service: JWTService = Depends(get_jwt_service)
):
    """
    Logout and blacklist tokens.
    
    Can blacklist specific tokens or all tokens for the user (logout_all=true).
    Blacklisted tokens cannot be used for authentication.
    """
    try:
        logged_out_count = 0
        
        # Validate and blacklist access token if provided
        if request.access_token:
            access_token = RequestValidator.validate_token(request.access_token, "access_token")
            await jwt_service.blacklist_token(access_token, TokenType.ACCESS)
            logged_out_count += 1
        
        # Validate and blacklist refresh token if provided
        if request.refresh_token:
            refresh_token = RequestValidator.validate_token(request.refresh_token, "refresh_token")
            await jwt_service.blacklist_token(refresh_token, TokenType.REFRESH)
            logged_out_count += 1
        
        # Handle logout from all devices
        if request.logout_all and (request.access_token or request.refresh_token):
            # Extract wallet address from one of the tokens to logout all sessions
            token = request.access_token or request.refresh_token
            payload = await jwt_service.verify_token(token, TokenType.ACCESS if request.access_token else TokenType.REFRESH)
            
            # Blacklist all tokens for this wallet
            additional_count = await jwt_service.blacklist_all_tokens(payload.wallet_address)
            logged_out_count += additional_count
        
        logger.info(f"Logout successful, blacklisted {logged_out_count} tokens")
        
        return LogoutResponseDto(
            success=True,
            message="Successfully logged out",
            logged_out_tokens=logged_out_count
        )
        
    except ValidationException as e:
        logger.warning(f"Validation failed for logout request: {e}")
        validation_exception_handler(request, e)
        
    except Exception as e:
        logger.error(f"Failed to logout: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": ErrorCode.INTERNAL_ERROR,
                    "message": "Logout failed",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }
        )


@router.get("/session/status", response_model=SessionStatusResponseDto)
async def get_session_status(
    authorization: str = Depends(lambda: None),  # Will be handled by JWT middleware
    jwt_service: JWTService = Depends(get_jwt_service)
):
    """
    Check the validity of the current session.
    
    Requires a valid JWT token in the Authorization header.
    Returns session information including expiration time.
    """
    try:
        # This endpoint will be protected by JWT middleware
        # For now, we'll extract token from Authorization header manually
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": {
                        "code": ErrorCode.INVALID_TOKEN,
                        "message": "Missing or invalid authorization header",
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                }
            )
        
        token = authorization.split(" ")[1]
        token = RequestValidator.validate_token(token, "access_token")
        
        # Verify token and get payload
        payload = await jwt_service.verify_token(token, TokenType.ACCESS)
        
        # Calculate remaining time
        remaining_seconds = int((payload.exp - datetime.utcnow()).total_seconds())
        
        return SessionStatusResponseDto(
            valid=True,
            wallet_address=payload.wallet_address,
            protocol=getattr(payload, 'protocol', None),
            expires_at=payload.exp,
            remaining_seconds=max(0, remaining_seconds)
        )
        
    except HTTPException:
        raise
        
    except Exception as e:
        logger.error(f"Failed to check session status: {str(e)}")
        return SessionStatusResponseDto(
            valid=False,
            wallet_address=None,
            protocol=None,
            expires_at=None,
            remaining_seconds=None
        )


@router.get("/protocols", response_model=ProtocolsResponseDto)
async def get_supported_protocols():
    """
    Get list of supported blockchain protocols and their detailed status.
    
    Returns information about each protocol including network, RPC status, and features.
    """
    try:
        from src.api.controller.auth.dto.output_dto import ProtocolInfo
        
        protocols = []
        for verifier in protocol_registry._verifiers.values():
            # Determine features based on protocol
            features = ["challenge_response", "signature_verification"]
            if verifier.config.protocol == BlockchainProtocol.NEAR:
                features.extend(["ed25519_signatures", "implicit_accounts", "named_accounts"])
            elif verifier.config.protocol == BlockchainProtocol.EVM:
                features.extend(["ecdsa_signatures", "ethereum_compatible"])
            
            # Get network information
            network = None
            chain_id = None
            if hasattr(verifier.config, 'network_id'):
                network = verifier.config.network_id
            elif hasattr(verifier.config, 'chain_id'):
                chain_id = verifier.config.chain_id
                network = "mainnet" if chain_id == 1 else f"chain_{chain_id}"
            
            protocol_info = ProtocolInfo(
                name=verifier.config.protocol.value,
                enabled=True,
                network=network,
                chain_id=chain_id,
                rpc_status="connected" if getattr(verifier, '_connection_established', True) else "offline",
                features=features
            )
            protocols.append(protocol_info)
        
        enabled_count = len([p for p in protocols if p.enabled])
        
        logger.info(f"Retrieved {len(protocols)} protocols, {enabled_count} enabled")
        
        return ProtocolsResponseDto(
            protocols=protocols,
            total_count=len(protocols),
            enabled_count=enabled_count
        )
        
    except Exception as e:
        logger.error(f"Failed to get protocols: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": ErrorCode.INTERNAL_ERROR,
                    "message": "Failed to retrieve protocols",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }
        )


@router.get("/account/{protocol}/{address}", response_model=AccountInfoResponseDto)
async def get_account_info(
    protocol: str,
    address: str
):
    """
    Get account information for a specific protocol and address.
    
    Validates the address format and returns basic account information.
    For production, this could be extended to fetch balance and other details.
    """
    try:
        # Validate protocol
        protocol_enum = RequestValidator.validate_protocol(protocol)
        
        # Validate address for the protocol
        validated_address = RequestValidator.validate_wallet_address(address, protocol_enum)
        
        # Get verifier for the protocol
        verifier = protocol_registry.get_verifier(protocol_enum)
        if not verifier:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": {
                        "code": ErrorCode.UNSUPPORTED_PROTOCOL,
                        "message": f"Protocol {protocol} is not registered",
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                }
            )
        
        # Determine account type based on protocol and address format
        account_type = None
        network = None
        
        if protocol_enum == BlockchainProtocol.NEAR:
            network = getattr(verifier.config, 'network_id', 'unknown')
            if len(validated_address) == 64 and all(c in '0123456789abcdef' for c in validated_address.lower()):
                account_type = "implicit"
            elif '.' in validated_address:
                account_type = "named"
            else:
                account_type = "top_level"
                
        elif protocol_enum == BlockchainProtocol.EVM:
            account_type = "externally_owned"  # Could be contract, but we can't determine without RPC
            chain_id = getattr(verifier.config, 'chain_id', None)
            network = "mainnet" if chain_id == 1 else f"chain_{chain_id}" if chain_id else "unknown"
        
        logger.info(f"Retrieved account info for {validated_address} on {protocol}")
        
        return AccountInfoResponseDto(
            address=validated_address,
            protocol=protocol_enum.value,
            valid=True,
            network=network,
            account_type=account_type,
            balance=None,  # Would require RPC calls - skip for MVP
            last_activity=None  # Would require RPC calls - skip for MVP
        )
        
    except ValidationException as e:
        logger.warning(f"Validation failed for account info request: {e}")
        validation_exception_handler(None, e)
        
    except HTTPException:
        raise
        
    except Exception as e:
        logger.error(f"Failed to get account info: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "code": ErrorCode.INTERNAL_ERROR,
                    "message": "Failed to retrieve account information",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }
        )

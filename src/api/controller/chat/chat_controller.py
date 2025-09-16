"""
Chat proxy controller for n8n workflow integration
"""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Request, HTTPException, Header, Depends, status

from src.core.service.chat.models.chat import (
    ChatRequest, ChatResponse, ChatErrorResponse, 
    UserContext, RateLimitInfo
)
from src.core.service.chat.n8n_client import N8nClient
from src.core.service.chat.chat_rate_limiter import ChatRateLimiter
from src.core.service.chat.chat_logger import ChatLogger
from src.core.service.auth.jwt_service import JWTService
from src.core.service.auth.models.token import TokenType
from src.core.logger.logger import get_logger
from src.infra.config.settings import get_settings
from src.infra.config.redis import get_redis
from src.core.service.auth.cache.token_store import TokenStore

logger = get_logger(__name__)
settings = get_settings()

# Initialize router
router = APIRouter(
    prefix="/chat",
    tags=["Chat"],
    responses={
        429: {"description": "Rate limit exceeded"},
        502: {"description": "Bad gateway - n8n workflow error"},
        504: {"description": "Gateway timeout - n8n workflow timeout"}
    }
)

# Initialize services (will be properly initialized on startup)
n8n_client = None
rate_limiter = None
chat_logger = None


async def get_jwt_service() -> JWTService:
    """Get JWT service with dependencies."""
    redis_client = await get_redis()
    token_store = TokenStore(redis_client)
    return JWTService(token_store)


async def init_chat_services():
    """Initialize chat services with Redis connection"""
    global n8n_client, rate_limiter, chat_logger
    
    try:
        # Get Redis connection
        redis_client = await get_redis()
        
        # Initialize services with Redis
        n8n_client = N8nClient()
        rate_limiter = ChatRateLimiter(redis_client)
        chat_logger = ChatLogger(redis_client)
        
        logger.info("Chat services initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize chat services: {str(e)}")
        # Initialize without Redis (limited functionality)
        n8n_client = N8nClient()
        rate_limiter = ChatRateLimiter(None)
        chat_logger = ChatLogger(None)


async def get_user_context(
    authorization: Optional[str] = Header(None),
    jwt_service: JWTService = Depends(get_jwt_service)
) -> UserContext:
    """
    Extract user context from JWT token if provided
    
    Args:
        authorization: Optional Authorization header
        jwt_service: JWT service instance
        
    Returns:
        UserContext with authentication information
    """
    if not authorization:
        # Guest user
        return UserContext(
            wallet_address=None,
            is_authenticated=False,
            user_type="guest"
        )
    
    try:
        # Remove 'Bearer ' prefix
        token = authorization.replace('Bearer ', '').strip()
        
        # Verify JWT token
        payload = await jwt_service.verify_token(token, TokenType.ACCESS)
        
        # Extract user information
        wallet_address = payload.get('wallet_address')
        wallet_type = payload.get('wallet_type', 'unknown')
        
        # Determine user type (could be enhanced with database lookup)
        user_type = "authenticated"
        # TODO: Check if user is premium based on database or claims
        
        return UserContext(
            wallet_address=wallet_address,
            is_authenticated=True,
            user_type=user_type,
            wallet_type=wallet_type
        )
        
    except Exception as e:
        logger.warning(
            f"Invalid JWT token in chat request: {str(e)}",
            extra={"error": str(e)}
        )
        # Treat as guest if token is invalid
        return UserContext(
            wallet_address=None,
            is_authenticated=False,
            user_type="guest"
        )


@router.post(
    "/",
    response_model=ChatResponse,
    summary="Chat Proxy Endpoint",
    description="Proxy chat requests to n8n workflows with authentication and rate limiting"
)
async def chat_proxy(
    request_body: ChatRequest,
    http_request: Request,
    user_context: UserContext = Depends(get_user_context)
):
    """
    Chat proxy endpoint that forwards requests to n8n workflows
    
    Features:
    - JWT authentication (optional for guests)
    - Rate limiting based on user type
    - Request logging and analytics
    - n8n workflow integration
    
    Rate Limits:
    - Guest users: 3 messages per 24 hours
    - Authenticated users: 100 messages per hour
    - Premium users: 500 messages per hour
    """
    start_time = datetime.utcnow()
    client_ip = http_request.client.host
    user_agent = http_request.headers.get("user-agent")
    
    try:
        # 1. Check rate limits
        is_allowed, rate_limit_info = await rate_limiter.check_rate_limit(
            user_context, client_ip
        )
        
        if not is_allowed:
            # Rate limit exceeded
            logger.warning(
                f"Rate limit exceeded for chat request",
                extra={
                    "session_id": request_body.sessionId,
                    "mode": request_body.mode.value,
                    "client_ip": client_ip,
                    "user_type": user_context.user_type
                }
            )
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=ChatErrorResponse(
                    error="Rate limit exceeded. Please try again later.",
                    code=429,
                    rateLimitInfo=rate_limit_info,
                    details={
                        "user_type": user_context.user_type,
                        "message": f"You have exceeded your message limit. "
                                  f"Limit resets at {rate_limit_info.reset_time}"
                    }
                ).dict()
            )
        
        # 2. Add user context to request
        request_body.userContext = user_context
        
        # 3. Send to n8n workflow
        logger.info(
            f"Forwarding chat request to n8n",
            extra={
                "session_id": request_body.sessionId,
                "mode": request_body.mode.value,
                "authenticated": user_context.is_authenticated
            }
        )
        
        try:
            n8n_response = await n8n_client.send_to_n8n(request_body, user_context)
        except TimeoutError as e:
            # n8n workflow timeout
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Log the timeout
            await chat_logger.log_interaction(
                session_id=request_body.sessionId,
                user_context=user_context,
                chat_input=request_body.chatInput,
                mode=request_body.mode,
                response={"error": "timeout"},
                duration=duration,
                client_ip=client_ip,
                user_agent=user_agent
            )
            
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=ChatErrorResponse(
                    error="The request took too long to process. Please try again.",
                    code=504,
                    rateLimitInfo=rate_limit_info,
                    details={"message": str(e)}
                ).dict()
            )
        except ConnectionError as e:
            # n8n connection error
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Log the error
            await chat_logger.log_interaction(
                session_id=request_body.sessionId,
                user_context=user_context,
                chat_input=request_body.chatInput,
                mode=request_body.mode,
                response={"error": "connection_failed"},
                duration=duration,
                client_ip=client_ip,
                user_agent=user_agent
            )
            
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=ChatErrorResponse(
                    error="Failed to connect to chat service. Please try again.",
                    code=502,
                    rateLimitInfo=rate_limit_info,
                    details={"message": str(e)}
                ).dict()
            )
        
        # 4. Calculate duration
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # 5. Log interaction
        await chat_logger.log_interaction(
            session_id=request_body.sessionId,
            user_context=user_context,
            chat_input=request_body.chatInput,
            mode=request_body.mode,
            response=n8n_response,
            duration=duration,
            client_ip=client_ip,
            user_agent=user_agent
        )
        
        # 6. Build response
        response = ChatResponse(
            output=n8n_response.get("output"),
            message=n8n_response.get("message"),
            sessionId=request_body.sessionId,
            timestamp=datetime.utcnow().isoformat() + "Z",
            rateLimitInfo=rate_limit_info,
            error=n8n_response.get("error")
        )
        
        logger.info(
            f"Chat request completed successfully",
            extra={
                "session_id": request_body.sessionId,
                "mode": request_body.mode.value,
                "duration": duration,
                "has_output": bool(response.output or response.message)
            }
        )
        
        return response
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
        
    except Exception as e:
        # Unexpected error
        logger.error(
            f"Unexpected error in chat proxy",
            extra={
                "session_id": request_body.sessionId,
                "error": str(e),
                "client_ip": client_ip
            },
            exc_info=True
        )
        
        # Try to get rate limit info for error response
        try:
            _, rate_limit_info = await rate_limiter.check_rate_limit(
                user_context, client_ip
            )
        except:
            rate_limit_info = None
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ChatErrorResponse(
                error="An unexpected error occurred. Please try again.",
                code=500,
                rateLimitInfo=rate_limit_info,
                details={"message": "Internal server error"}
            ).dict()
        )


@router.get(
    "/stats",
    summary="Get Chat Statistics",
    description="Get chat usage statistics (admin endpoint)"
)
async def get_chat_stats(
    date: Optional[str] = None,
    authorization: str = Header(...),
    jwt_service: JWTService = Depends(get_jwt_service)
):
    """
    Get chat statistics for monitoring and analytics
    
    Requires admin authentication
    """
    try:
        # Verify admin token
        token = authorization.replace('Bearer ', '').strip()
        payload = await jwt_service.verify_token(token, TokenType.ACCESS)
        
        # TODO: Check if user is admin
        # For now, just check if authenticated
        if not payload.get('wallet_address'):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        # Get statistics
        stats = await chat_logger.get_daily_statistics(date)
        
        return {
            "success": True,
            "data": stats
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting chat stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve statistics"
        )

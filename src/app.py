import json
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from src.infra.config.settings import settings
from src.core.logger.logger import logger
from src.api.router import health, protected, mock_endpoint, auth, chat, funding, contract
from src.api.middleware.security.rate_limiter import RateLimitMiddleware
from src.api.middleware.security.audit_logger import AuditLoggingMiddleware
from src.api.middleware.logging.request_logging import RequestLoggingMiddleware
from src.core.exceptions.handler import ServiceError, GlobalErrorHandler

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="""
MintroAI Blockchain Services API - Multi-protocol authentication, smart contract generation, and DeFi services.

## Services
- **Authentication**: EVM and NEAR Protocol wallet authentication
- **Smart Contracts**: Token and vesting contract generation, compilation, pricing
- **DeFi**: NEAR Chain Signatures and cross-chain funding
- **Chat**: AI-powered assistance and WebSocket support

## Authentication
All protected endpoints require JWT Bearer token authentication.
        """,
        version=settings.APP_VERSION,
        docs_url="/",
        redoc_url="/redoc",
        contact={
            "name": "MintroAI Team",
            "url": "https://mintroai.com",
            "email": "support@mintroai.com"
        },
        license_info={
            "name": "MIT License",
            "url": "https://opensource.org/licenses/MIT"
        },
        servers=[
            {
                "url": "http://localhost:8000",
                "description": "Development server"
            },
            {
                "url": "https://api.mintroai.com",
                "description": "Production server"
            }
        ]
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
        max_age=600,  # 10 minutes
    )

    # Request logging middleware (should be first to catch all requests)
    app.add_middleware(RequestLoggingMiddleware)

    # Audit logging middleware
    app.add_middleware(AuditLoggingMiddleware)

    # Rate limiting middleware
    app.add_middleware(RateLimitMiddleware)

    # Add centralized error handlers
    app.add_exception_handler(ServiceError, GlobalErrorHandler.service_error_handler)
    app.add_exception_handler(RequestValidationError, GlobalErrorHandler.validation_error_handler)
    app.add_exception_handler(Exception, GlobalErrorHandler.general_exception_handler)

    # Include routers
    from src.api.router import websocket, config, webhook
    
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(chat.router, prefix="/api/v1")
    app.include_router(funding.router)  # Funding router uses /api/v1 prefix
    app.include_router(contract.router)  # Contract router with /api/v1/contract prefix
    app.include_router(protected.router, prefix="/api/v1")
    app.include_router(mock_endpoint.router, prefix="/api/v1")
    
    # Include Node.js compatible endpoints (without prefix)
    app.include_router(config.router)  # /config endpoints
    app.include_router(webhook.router)  # /webhook endpoint
    app.include_router(websocket.router)  # /ws endpoint

    # Initialize WebSocket manager
    from src.core.service.websocket.manager import ConnectionManager
    app.state.ws_manager = ConnectionManager()
    
    # Initialize configurations store - exactly like Node.js
    app.state.configurations = {}
    
    @app.on_event("startup")
    async def startup_event():
        logger.info(json.dumps({
            "message": "Starting API Gateway",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION
        }))
        
        # Initialize protocol verifiers
        try:
            from src.api.router.auth import init_protocols
            await init_protocols()
        except Exception as e:
            logger.error(f"Failed to initialize protocols on startup: {str(e)}")
        
        # Initialize chat services
        try:
            from src.api.controller.chat.chat_controller import init_chat_services
            await init_chat_services()
        except Exception as e:
            logger.error(f"Failed to initialize chat services on startup: {str(e)}")

    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info(json.dumps({
            "message": "Shutting down API Gateway",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION
        }))

    return app
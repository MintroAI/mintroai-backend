import json
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.infra.config.settings import settings
from src.core.logger.logger import logger
from src.api.router import health, protected, mock_endpoint, auth
from src.api.middleware.security.rate_limiter import RateLimitMiddleware
from src.api.middleware.security.audit_logger import AuditLoggingMiddleware
from src.api.middleware.logging.request_logging import RequestLoggingMiddleware

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="""
# MintroAI Multi-Protocol Authentication API

A comprehensive authentication system supporting multiple blockchain protocols.

## Supported Protocols
- **EVM**: Ethereum and EVM-compatible chains (Polygon, BSC, etc.)
- **NEAR**: NEAR Protocol blockchain

## Authentication Flow
1. **Challenge Creation**: Generate a unique challenge message
2. **Signature Verification**: Sign the challenge with your wallet
3. **Token Generation**: Receive JWT tokens for authenticated access
4. **Session Management**: Manage active sessions and refresh tokens

## Key Features
- 🔒 **Multi-Protocol Support**: EVM and NEAR protocols
- 🚀 **Rate Limiting**: Protection against abuse
- 📊 **Comprehensive Monitoring**: Metrics and health checks
- 🛡️ **Security**: Audit logging and IP blocking
- 📚 **Complete Documentation**: OpenAPI 3.0 specification

## Quick Start
```bash
# 1. Create a challenge
curl -X POST "/api/v1/auth/challenge" \\
     -H "Content-Type: application/json" \\
     -d '{"wallet_address": "0x...", "protocol": "evm"}'

# 2. Sign the challenge message with your wallet

# 3. Verify the signature
curl -X POST "/api/v1/auth/verify" \\
     -H "Content-Type: application/json" \\
     -d '{"wallet_address": "0x...", "signature": "0x...", "protocol": "evm"}'
```
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

    # Include routers
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(protected.router, prefix="/api/v1")
    app.include_router(mock_endpoint.router, prefix="/api/v1")

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

    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info(json.dumps({
            "message": "Shutting down API Gateway",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION
        }))

    return app
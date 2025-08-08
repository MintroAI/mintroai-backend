import json
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.infra.config.settings import settings
from src.core.logger.logger import logger
from src.api.router import health, protected, mock_endpoint
from src.api.middleware.security.rate_limiter import RateLimitMiddleware
from src.api.middleware.logging.request_logging import RequestLoggingMiddleware

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="API Gateway for MintroAI",
        version=settings.APP_VERSION,
        docs_url="/",
        redoc_url="/redoc"
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

    # Rate limiting middleware
    app.add_middleware(RateLimitMiddleware)

    # Include routers
    app.include_router(health.router, prefix="/api/v1")
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
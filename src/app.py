from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.infra.config.settings import settings
from src.core.logger.logger import logger
from src.api.router import health, protected, mock_endpoint
from src.api.middleware.security.rate_limiter import RateLimitMiddleware

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

    # Rate limiting middleware
    app.add_middleware(RateLimitMiddleware)

    # Include routers
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(protected.router, prefix="/api/v1")
    app.include_router(mock_endpoint.router, prefix="/api/v1")

    @app.on_event("startup")
    async def startup_event():
        logger.info("Starting API Gateway")

    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info("Shutting down API Gateway")

    return app
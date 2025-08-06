from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.infra.config.settings import settings
from src.core.logger.logger import logger
from src.api.router import health, protected

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
        allow_origins=["*"],  # In production, replace with specific origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(protected.router, prefix="/api/v1")

    @app.on_event("startup")
    async def startup_event():
        logger.info("Starting API Gateway")

    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info("Shutting down API Gateway")

    return app
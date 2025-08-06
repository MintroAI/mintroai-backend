from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.infra.config.settings import settings
from src.core.logger.logger import logger


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="Backend for MintroAI",
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

    @app.on_event("startup")
    async def startup_event():
        logger.info("Starting up application")
        # Database connection can be initialized here

    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info("Shutting down application")
        # Cleanup tasks can be added here

    # Include routers here
    # app.include_router(some_router, prefix="/api/v1", tags=["some_tag"])

    return app
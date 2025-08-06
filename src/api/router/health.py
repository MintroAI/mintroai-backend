from fastapi import APIRouter, status
from src.core.logger.logger import logger

router = APIRouter()

@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """
    Health check endpoint to verify API Gateway status
    Returns 200 OK if the service is running
    """
    logger.info("Health check requested")
    return {
        "status": "healthy",
        "service": "api_gateway",
        "version": "1.0.0"
    }
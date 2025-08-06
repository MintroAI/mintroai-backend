import json
from fastapi import APIRouter, status, Request
from datetime import datetime

from src.core.logger.logger import logger

router = APIRouter()

@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check(request: Request):
    """
    Health check endpoint to verify API Gateway status
    Returns 200 OK if the service is running
    """
    # Get correlation ID from request
    correlation_id = request.headers.get("X-Request-ID", "N/A")
    
    # Check service dependencies (mock for now)
    dependencies = {
        "database": "healthy",
        "cache": "healthy",
        "message_queue": "healthy"
    }
    
    # Create health check response
    health_data = {
        "status": "healthy",
        "service": "api_gateway",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "request_id": correlation_id,
        "dependencies": dependencies
    }
    
    # Log health check with context
    logger.info(json.dumps({
        "type": "health_check",
        "service_status": "healthy",
        "dependencies": dependencies,
        "request_id": correlation_id,
        "timestamp": health_data["timestamp"]
    }))
    
    return health_data
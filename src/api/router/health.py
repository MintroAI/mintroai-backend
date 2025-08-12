import json
from fastapi import APIRouter, status, Request
from datetime import datetime
from typing import Dict, Any

from src.core.logger.logger import logger
from src.core.service.auth.protocols.base import protocol_registry, BlockchainProtocol
from src.infra.config.redis import get_redis
from src.api.controller.auth.dto.output_dto import HealthCheckResponseDto
from src.api.utils.metrics import get_metrics

router = APIRouter()

async def check_redis_health() -> Dict[str, str]:
    """Check Redis connection health."""
    try:
        redis_client = await get_redis()
        await redis_client.ping()
        return {"status": "healthy", "message": "Connected"}
    except Exception as e:
        return {"status": "unhealthy", "message": f"Connection failed: {str(e)}"}


async def check_protocol_health() -> Dict[str, Dict[str, Any]]:
    """Check health of all registered protocol verifiers."""
    protocols = {}
    
    for protocol_enum, verifier in protocol_registry._verifiers.items():
        try:
            # Check if verifier is initialized
            is_connected = getattr(verifier, '_connection_established', True)
            
            # Get basic info
            protocol_info = {
                "status": "healthy" if is_connected else "degraded",
                "network": getattr(verifier.config, 'network_id', None) or getattr(verifier.config, 'chain_id', None),
                "connection": "connected" if is_connected else "offline",
                "last_check": datetime.utcnow().isoformat() + "Z"
            }
            
            # Add protocol-specific info
            if protocol_enum == BlockchainProtocol.NEAR:
                protocol_info.update({
                    "rpc_urls": getattr(verifier.config, 'rpc_urls', []),
                    "features": ["ed25519", "implicit_accounts", "named_accounts"]
                })
            elif protocol_enum == BlockchainProtocol.EVM:
                protocol_info.update({
                    "chain_id": getattr(verifier.config, 'chain_id', None),
                    "features": ["ecdsa", "ethereum_compatible"]
                })
            
            protocols[protocol_enum.value] = protocol_info
            
        except Exception as e:
            protocols[protocol_enum.value] = {
                "status": "unhealthy",
                "error": str(e),
                "last_check": datetime.utcnow().isoformat() + "Z"
            }
    
    return protocols


@router.get("/health", response_model=HealthCheckResponseDto, status_code=status.HTTP_200_OK)
async def health_check(request: Request):
    """
    Enhanced health check endpoint with protocol-specific checks.
    Returns detailed status of all system components including auth protocols.
    """
    # Get correlation ID from request
    correlation_id = request.headers.get("X-Request-ID", "N/A")
    
    # Check Redis health
    redis_health = await check_redis_health()
    
    # Check protocol health
    protocol_health = await check_protocol_health()
    
    # Get metrics health
    metrics = get_metrics()
    metrics_health = metrics.get_health_metrics()
    
    # Check overall service health
    services = {
        "redis": redis_health["status"],
        "auth_protocols": "healthy" if all(
            p.get("status") in ["healthy", "degraded"] for p in protocol_health.values()
        ) else "unhealthy",
        "metrics": metrics_health["status"],
        "api_gateway": "healthy"
    }
    
    # Determine overall status
    overall_status = "healthy"
    if any(status == "unhealthy" for status in services.values()):
        overall_status = "unhealthy"
    elif any(status == "degraded" for status in services.values()):
        overall_status = "degraded"
    
    # Create health check response
    health_response = HealthCheckResponseDto(
        status=overall_status,
        timestamp=datetime.utcnow(),
        protocols=protocol_health,
        services=services
    )
    
    # Log health check with context
    logger.info(json.dumps({
        "type": "health_check",
        "overall_status": overall_status,
        "services": services,
        "protocol_count": len(protocol_health),
        "request_id": correlation_id,
        "timestamp": health_response.timestamp.isoformat() + "Z"
    }))
    
    return health_response


@router.get("/metrics", status_code=status.HTTP_200_OK)
async def get_metrics_endpoint():
    """
    Get authentication metrics and statistics.
    Returns success/failure rates, protocol usage, and performance data.
    """
    try:
        metrics = get_metrics()
        metrics_data = metrics.get_metrics_summary()
        
        logger.info(json.dumps({
            "type": "metrics_request",
            "total_attempts": metrics_data["overall"]["total_auth_attempts"],
            "success_rate": metrics_data["overall"]["success_rate_percent"],
            "active_sessions": metrics_data["overall"]["active_sessions"],
            "timestamp": metrics_data["timestamp"]
        }))
        
        return metrics_data
        
    except Exception as e:
        logger.error(f"Failed to retrieve metrics: {str(e)}")
        return {
            "error": "Failed to retrieve metrics",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
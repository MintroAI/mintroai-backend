import json
from fastapi import APIRouter, status, Request
from datetime import datetime
from typing import Dict, Any

from src.core.logger.logger import logger
from src.core.service.auth.protocols.base import protocol_registry, BlockchainProtocol
from src.core.service.funding.funding_service import FundingService
from src.infra.config.redis import get_redis
from src.api.controller.auth.dto.output_dto import HealthCheckResponseDto
from src.api.utils.metrics import get_metrics

router = APIRouter()

from src.infra.config.settings import settings

async def check_redis_health() -> Dict[str, str]:
    """Check Redis connection health."""
    try:
        redis_client = await get_redis()
        await redis_client.ping()
        return {"status": "healthy", "message": "Connected"}
    except Exception as e:
        return {"status": "unhealthy", "message": f"Connection failed: {str(e)}"}


async def check_funding_health() -> Dict[str, Any]:
    """Check funding service health."""
    try:
        funding_service = FundingService()
        
        # Check if funding service is configured
        if not funding_service.funder_account:
            return {
                "status": "not_configured",
                "message": "Funding service not configured - missing private key"
            }
        
        # Get funding status
        status_response = await funding_service.get_funding_status()
        
        if status_response.configured:
            # Count healthy networks
            healthy_networks = 0
            total_networks = len(status_response.balances) if status_response.balances else 0
            
            if status_response.balances:
                for network_balance in status_response.balances.values():
                    if network_balance.can_fund and not network_balance.error:
                        healthy_networks += 1
            
            return {
                "status": "healthy" if healthy_networks > 0 else "degraded",
                "message": f"{healthy_networks}/{total_networks} networks operational",
                "funder_address": status_response.funder_address,
                "networks": total_networks,
                "healthy_networks": healthy_networks
            }
        else:
            return {
                "status": "unhealthy",
                "message": status_response.message or "Funding service not configured"
            }
            
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"Funding service check failed: {str(e)}"
        }


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


@router.get("/health", status_code=status.HTTP_200_OK)
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
    
    # Check funding service health
    funding_health = await check_funding_health()
    
    # Get metrics health
    metrics = get_metrics()
    metrics_health = metrics.get_health_metrics()
    
    # Get WebSocket status - like Node.js: wss.clients.size + ' clients connected'
    websocket_status = "not initialized"
    websocket_clients = 0
    try:
        if hasattr(request.app.state, 'ws_manager'):
            websocket_clients = request.app.state.ws_manager.get_connection_count()
            websocket_status = f"{websocket_clients} clients connected"
    except:
        pass
    
    # Check overall service health
    services = {
        "redis": redis_health["status"],
        "auth_protocols": "healthy" if all(
            p.get("status") in ["healthy", "degraded"] for p in protocol_health.values()
        ) else "unhealthy",
        "funding": funding_health["status"],
        "websocket": websocket_status,
        "metrics": metrics_health["status"],
        "api_gateway": "healthy"
    }
    
    # Determine overall status
    overall_status = "healthy"
    if any(status == "unhealthy" for status in services.values()):
        overall_status = "unhealthy"
    elif any(status == "degraded" for status in services.values()):
        overall_status = "degraded"
    
    # Return simple health response like Node.js
    # Node.js: res.json({ status: 'ok', services: { websocket: ..., funding: ... } })
    return {
        "status": overall_status if overall_status == "healthy" else "degraded",
        "services": services,
        "protocols": protocol_health,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@router.get("/health")
async def simple_health(request: Request):
    """
    Simple health endpoint exactly like Node.js server.
    Returns basic status with WebSocket and funding info.
    """
    # Get WebSocket client count
    ws_client_count = 0
    if hasattr(request.app.state, 'ws_manager'):
        ws_client_count = request.app.state.ws_manager.get_connection_count()
    
    # Check if funding is configured  
    funding_configured = "configured" if settings.FUNDER_PRIVATE_KEY else "not configured"
    
    return {
        "status": "ok",
        "services": {
            "websocket": f"{ws_client_count} clients connected",
            "funding": funding_configured
        }
    }


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
"""
High-performance HTTP client configuration for scale.
NO RETRY mechanisms - designed for 10k+ requests/second.
NO GLOBAL instances - each service manages its own lifecycle.
"""

import httpx
from typing import Optional, Dict, Any

from src.infra.config.settings import get_settings

settings = get_settings()


class HTTPClientConfig:
    """HTTP client configuration optimized for high-scale applications"""
    
    @classmethod
    def get_timeout(cls, service: str) -> float:
        """Get timeout for specific service"""
        timeout_map = {
            "default": settings.HTTP_DEFAULT_TIMEOUT,
            "contract": settings.HTTP_CONTRACT_TIMEOUT,
            "n8n_chat": settings.HTTP_N8N_CHAT_TIMEOUT,
            "n8n_general": settings.HTTP_N8N_GENERAL_TIMEOUT,
            "near_rpc": settings.HTTP_NEAR_RPC_TIMEOUT,
        }
        return timeout_map.get(service, settings.HTTP_DEFAULT_TIMEOUT)
    
    @classmethod
    def get_base_headers(cls) -> Dict[str, str]:
        """Get base headers for HTTP requests"""
        return {
            "User-Agent": f"MintroAI-Backend/{settings.APP_VERSION}",
            "Accept": "application/json",
        }
    
    @classmethod
    def create_client_config(cls, service: str = "default", timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Create HTTP client configuration (NOT the client itself).
        Each service should create its own client instance using this config.
        
        Args:
            service: Service name for timeout configuration
            timeout: Override timeout (optional)
            
        Returns:
            Dict with client configuration
        """
        client_timeout = timeout or cls.get_timeout(service)
        
        return {
            "timeout": client_timeout,
            "limits": httpx.Limits(
                max_connections=settings.HTTP_MAX_CONNECTIONS,
                max_keepalive_connections=settings.HTTP_MAX_KEEPALIVE_CONNECTIONS
            ),
            "headers": cls.get_base_headers(),
            "follow_redirects": False,  # Explicit control
            # NO RETRIES - fail fast for high-scale
        }


# Utility function for one-off requests (use sparingly)
def create_temp_client(service: str = "default", **kwargs) -> httpx.AsyncClient:
    """
    Create a temporary HTTP client for one-off requests.
    WARNING: Remember to close the client after use!
    
    Args:
        service: Service name for configuration
        **kwargs: Additional httpx.AsyncClient arguments
        
    Returns:
        httpx.AsyncClient: Configured client (must be closed!)
    """
    config = HTTPClientConfig.create_client_config(service)
    config.update(kwargs)
    return httpx.AsyncClient(**config)

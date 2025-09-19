"""Configuration management endpoints - exactly like Node.js server."""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any, Optional

from src.core.logger.logger import logger

router = APIRouter()


class ConfigRequest(BaseModel):
    """Request model for setting configuration."""
    chatId: str
    config: Dict[str, Any]


class ConfigResponse(BaseModel):
    """Response model for configuration operations."""
    message: str
    data: Optional[Dict[str, Any]] = None


@router.get("/config")
async def get_configuration(chatId: str, request: Request) -> ConfigResponse:
    """
    Get configuration for a specific chat.
    Exactly like Node.js: app.get('/config')
    
    Query params:
        chatId: The chat ID to get configuration for
    """
    if not chatId:
        raise HTTPException(status_code=400, detail="chatId is required.")
    
    # Get configurations from app state
    configurations = request.app.state.configurations
    
    config = configurations.get(chatId)
    
    if not config:
        raise HTTPException(
            status_code=404, 
            detail=f"No configuration found for chatId: {chatId}"
        )
    
    return ConfigResponse(
        message="Configuration retrieved successfully!",
        data=config
    )


@router.post("/config")
async def set_configuration(request_data: ConfigRequest, request: Request) -> ConfigResponse:
    """
    Set configuration for a specific chat.
    Exactly like Node.js: app.post('/config')
    
    Body:
        chatId: The chat ID
        config: The configuration object
    """
    if not request_data.chatId or not request_data.config:
        raise HTTPException(status_code=400, detail="chatId and config are required.")
    
    # Get configurations and WebSocket manager from app state
    configurations = request.app.state.configurations
    ws_manager = request.app.state.ws_manager
    
    # Store configuration
    configurations[request_data.chatId] = request_data.config
    
    # Broadcast the configuration update to WebSocket clients
    await ws_manager.broadcast({
        "type": "configUpdated",
        "chatId": request_data.chatId,
        "config": request_data.config
    })
    
    logger.info(f"Config saved for: {request_data.chatId}, config: {configurations[request_data.chatId]}")
    
    return ConfigResponse(
        message="Configuration has been successfully saved!",
        data=configurations[request_data.chatId]
    )

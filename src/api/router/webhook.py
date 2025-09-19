"""Webhook endpoint for receiving external events - exactly like Node.js server."""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Any, Dict

from src.core.logger.logger import logger

router = APIRouter()


class WebhookResponse(BaseModel):
    """Response model for webhook endpoint."""
    message: str


@router.post("/webhook")
async def webhook_handler(payload: Dict[str, Any], request: Request) -> WebhookResponse:
    """
    Handle webhook events and broadcast to WebSocket clients.
    Exactly like Node.js: app.post('/webhook')
    
    Body:
        payload: Any JSON payload from the webhook
    """
    # Get WebSocket manager from app state
    ws_manager = request.app.state.ws_manager
    
    # Broadcast the webhook data to WebSocket clients
    await ws_manager.broadcast({
        "type": "webhookReceived",
        "data": payload
    })
    
    logger.info(f"Webhook received and broadcasted: {payload}")
    
    return WebhookResponse(message="Webhook processed and broadcasted")

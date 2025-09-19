"""WebSocket router for real-time communication."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from src.core.logger.logger import logger

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time communication.
    Simple implementation like Node.js server.
    
    Clients can connect to this endpoint to receive real-time updates
    about funding events and other broadcasts.
    """
    # Get manager from app state - WebSocket has app attribute
    manager = websocket.app.state.ws_manager
    
    # Accept connection
    await manager.connect(websocket)
    
    try:
        while True:
            # Wait for messages from client
            data = await websocket.receive_text()
            
            # Log received message - like Node.js: console.log('Received via WebSocket:', message.toString())
            logger.info(f"Received via WebSocket: {data}")
            
            # For now, just echo back (can be extended later)
            # In Node.js, messages are just logged, no response
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
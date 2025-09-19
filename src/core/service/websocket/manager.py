"""WebSocket connection manager for real-time communication."""

import json
from typing import List
from fastapi import WebSocket

from src.core.logger.logger import logger


class ConnectionManager:
    """Manages WebSocket connections and broadcasting."""
    
    def __init__(self):
        """Initialize the connection manager."""
        # Active connections list - simple like Node.js wss.clients
        self.active_connections: List[WebSocket] = []
        
    async def connect(self, websocket: WebSocket):
        """
        Accept a new WebSocket connection.
        
        Args:
            websocket: The WebSocket connection
        """
        await websocket.accept()
        self.active_connections.append(websocket)
        
        # Send welcome message - exactly like Node.js
        await websocket.send_json({
            "message": "Welcome to the WebSocket server!"
        })
        
        logger.info("New WebSocket client connected")
        
    def disconnect(self, websocket: WebSocket):
        """
        Remove a WebSocket connection.
        
        Args:
            websocket: The WebSocket connection to remove
        """
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected")
            
    async def broadcast(self, data: dict):
        """
        Broadcast a message to all connected clients.
        Exactly like Node.js broadcast function.
        
        Args:
            data: The data to broadcast (will be JSON serialized)
        """
        disconnected = []
        for connection in self.active_connections:
            try:
                # Send JSON just like Node.js: client.send(JSON.stringify(data))
                await connection.send_json(data)
            except Exception as e:
                # If send fails, mark for disconnection
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)
    
    def get_connection_count(self) -> int:
        """
        Get the number of active connections.
        Like Node.js: wss.clients.size
        """
        return len(self.active_connections)
"""
Live Threat Feed WebSocket — AegisShield
==========================================
Stream real-time detection events to analyst consoles via WS /ws/feed.
Includes ConnectionManager for robust lifecycle and broadcast handling.
"""

import json
import asyncio
import logging
from typing import List, Dict, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket connections for live feed streaming."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Active: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected. Active: %d", len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast payload to all active clients with bounded timeout; auto-evict dead connections."""
        if not self.active_connections:
            return

        text = json.dumps(message)
        dead = []
        for connection in list(self.active_connections):
            try:
                await asyncio.wait_for(connection.send_text(text), timeout=1.0)
            except Exception as e:
                logger.warning("Error pushing WS message to client: %s", e)
                dead.append(connection)

        for connection in dead:
            self.disconnect(connection)


manager = ConnectionManager()


@router.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    """
    Live threat feed over WebSocket.
    Pushes newly analyzed detections directly to analyst consoles.
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep socket open and accept incoming heartbeats/pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.warning("WebSocket unexpected disconnect: %s", e)
        manager.disconnect(websocket)


async def broadcast_detection(payload: Dict[str, Any]):
    """Helper invoked by analyzer routes to broadcast new detection event."""
    try:
        await manager.broadcast(payload)
    except Exception as e:
        logger.warning("broadcast_detection failed (non-blocking): %s", e)

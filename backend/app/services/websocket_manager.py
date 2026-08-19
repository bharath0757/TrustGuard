"""Real-time WebSocket connection manager for live guardian exam monitoring."""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Manages active WebSocket connections grouped by exam_id.
    Supports thread-safe asynchronous broadcasting of lifecycle events,
    student activity updates, consensus progression, and security alerts.
    """

    def __init__(self):
        # Mapping: exam_id -> set of active WebSockets
        self._exam_connections: Dict[str, Set[WebSocket]] = {}
        # Global connections (e.g. system admins, auditors)
        self._global_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, exam_id: Optional[str] = None):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            if exam_id:
                if exam_id not in self._exam_connections:
                    self._exam_connections[exam_id] = set()
                self._exam_connections[exam_id].add(websocket)
            else:
                self._global_connections.add(websocket)
        logger.info(f"WebSocket client connected for exam_id={exam_id}")

    async def disconnect(self, websocket: WebSocket, exam_id: Optional[str] = None):
        """Unregister a disconnected WebSocket."""
        async with self._lock:
            if exam_id and exam_id in self._exam_connections:
                self._exam_connections[exam_id].discard(websocket)
                if not self._exam_connections[exam_id]:
                    del self._exam_connections[exam_id]
            self._global_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected for exam_id={exam_id}")

    async def broadcast_to_exam(self, exam_id: str, event_type: str, payload: dict):
        """
        Broadcast an event to all guardians/clients monitoring a specific exam.
        Also delivers to global listeners.
        """
        message = {
            "type": event_type,
            "exam_id": exam_id,
            "payload": payload,
        }
        json_str = json.dumps(message, default=str)

        targets: List[WebSocket] = []
        async with self._lock:
            if exam_id in self._exam_connections:
                targets.extend(list(self._exam_connections[exam_id]))
            targets.extend(list(self._global_connections))

        if not targets:
            return

        dead_sockets: List[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(json_str)
            except Exception as exc:
                logger.warning(f"Failed to send WS message to client: {exc}")
                dead_sockets.append(ws)

        if dead_sockets:
            async with self._lock:
                for ws in dead_sockets:
                    if exam_id in self._exam_connections:
                        self._exam_connections[exam_id].discard(ws)
                    self._global_connections.discard(ws)

    async def broadcast_global(self, event_type: str, payload: dict):
        """Broadcast a global event to all connected clients across all exams."""
        message = {
            "type": event_type,
            "payload": payload,
        }
        json_str = json.dumps(message, default=str)

        targets: List[WebSocket] = []
        async with self._lock:
            for s in self._exam_connections.values():
                targets.extend(list(s))
            targets.extend(list(self._global_connections))

        for ws in targets:
            try:
                await ws.send_text(json_str)
            except Exception:
                pass


# Global singleton instance
_ws_manager = WebSocketManager()


def get_ws_manager() -> WebSocketManager:
    """Return the global WebSocketManager instance."""
    return _ws_manager

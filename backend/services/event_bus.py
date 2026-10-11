"""
Q-Chain Event Bus & WebSocket Manager
=====================================
Manages live WebSocket subscriptions and broadcasts AgentEvents and McpCallLogs.
Provides a central decoupled stream for real-time dashboard UI updates.

Owner: Member 3 (Backend and MCP Engineer)
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Set
from fastapi import WebSocket, WebSocketDisconnect

from shared.models import AgentEvent, McpCallLog

logger = logging.getLogger("qchain.event_bus")


class EventBus:
    """Singleton event broadcaster for real-time WebSocket distribution."""

    def __init__(self):
        self._active_connections: Set[WebSocket] = set()
        self._event_history: List[Dict[str, Any]] = []
        self._mcp_call_history: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        """Accepts a new WebSocket connection and adds it to the active pool."""
        await websocket.accept()
        async with self._lock:
            self._active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Active clients: {len(self._active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        """Removes a disconnected WebSocket from the active pool."""
        async with self._lock:
            self._active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Active clients: {len(self._active_connections)}")

    async def broadcast_agent_event(self, event: AgentEvent):
        """Dispatches an AgentEvent to all connected clients and records history."""
        dump = event.model_dump(mode="json")
        payload = {
            "type": "agent_event",
            "data": dump,
            "payload": {
                **dump,
                "agent": dump.get("agent_name"),
                "type": dump.get("event_type"),
            }
        }
        async with self._lock:
            self._event_history.append(payload)
            # Retain last 200 events in memory
            if len(self._event_history) > 200:
                self._event_history.pop(0)

        await self._broadcast_raw(payload)

    async def broadcast_mcp_log(self, log_entry: McpCallLog):
        """Dispatches an McpCallLog to all connected clients and records history."""
        dump = log_entry.model_dump(mode="json")
        payload = {
            "type": "mcp_call_log",
            "data": dump,
            "payload": {
                **dump,
                "server": dump.get("server_name"),
                "tool": dump.get("tool_name"),
            }
        }
        async with self._lock:
            self._mcp_call_history.append(payload)
            if len(self._mcp_call_history) > 200:
                self._mcp_call_history.pop(0)

        await self._broadcast_raw(payload)

    async def broadcast_scan_status(self, scan_id: str, status: str, progress: int, current_agent: str = None):
        """Broadcasts overall scan progress updates."""
        payload = {
            "type": "scan_status",
            "data": {
                "scan_id": scan_id,
                "status": status,
                "progress": progress,
                "current_agent": current_agent
            }
        }
        await self._broadcast_raw(payload)

    async def _broadcast_raw(self, payload: Dict[str, Any]):
        """Internal broadcast loop with dead-connection pruning."""
        message_text = json.dumps(payload)
        dead_connections = set()

        async with self._lock:
            connections = list(self._active_connections)

        for connection in connections:
            try:
                await connection.send_text(message_text)
            except Exception as e:
                logger.warning(f"Error sending to WebSocket client: {e}")
                dead_connections.add(connection)

        if dead_connections:
            async with self._lock:
                for dead in dead_connections:
                    self._active_connections.discard(dead)

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent agent events for initial dashboard hydration."""
        return self._event_history[-limit:]

    def get_recent_mcp_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent MCP tool call logs for initial dashboard hydration."""
        return self._mcp_call_history[-limit:]


# Global singleton instance
event_bus = EventBus()

"""
WebSocket Event Streaming Router
================================
Streams live AgentEvents and McpCallLogs to the frontend dashboard.

Owner: Member 3 (Backend Engineer)
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List, Dict, Any

from backend.services.event_bus import event_bus

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/events")
@router.websocket("/ws")
async def websocket_event_endpoint(websocket: WebSocket):
    """
    Real-time bidirectional WebSocket stream for dashboard UI.
    Streams agent activity, tool calls, and scan progress events.
    """
    await event_bus.connect(websocket)
    try:
        while True:
            # Keep-alive ping/pong receiver
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        await event_bus.disconnect(websocket)
    except Exception:
        await event_bus.disconnect(websocket)


@router.get("/api/events/recent")
def get_recent_events(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns recent agent events for initial dashboard hydration."""
    return event_bus.get_recent_events(limit)


@router.get("/api/mcp/logs")
def get_recent_mcp_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns recent MCP tool call telemetry logs."""
    return event_bus.get_recent_mcp_logs(limit)

"""
WebSocket Live Stream Integration Test
Verifies that connecting to /ws/events receives AgentEvents and McpCallLogs.
"""

import json
import pytest
from backend.services.event_bus import event_bus
from shared.models import AgentEvent, AgentEventType, McpCallLog


@pytest.mark.asyncio
async def test_websocket_event_broadcasting():
    received_payloads = []

    class MockWebSocket:
        async def accept(self):
            pass

        async def send_text(self, text: str):
            received_payloads.append(json.loads(text))

    mock_ws = MockWebSocket()
    await event_bus.connect(mock_ws)

    try:
        # Emit an agent event
        evt = AgentEvent(
            event_id="EVT-TEST-001",
            scan_id="SCAN-TEST",
            agent_name="AnalysisAgent",
            event_type=AgentEventType.AGENT_STARTED,
            message="Analysis Agent started scanning repository",
        )
        await event_bus.broadcast_agent_event(evt)

        # Emit an MCP log
        mcp_log = McpCallLog(
            call_id="CALL-TEST-001",
            scan_id="SCAN-TEST",
            server_name="code-analysis",
            tool_name="scan_directory",
            arguments={"directory_path": "samples/token_wallet"},
            result_summary="Discovered 5 vulnerable classical primitives.",
            duration_ms=12.5,
            status="success",
        )
        await event_bus.broadcast_mcp_log(mcp_log)

        # Verify both payloads reached the mock client
        assert len(received_payloads) == 2
        assert received_payloads[0]["type"] == "agent_event"
        assert received_payloads[0]["data"]["agent_name"] == "AnalysisAgent"
        assert received_payloads[1]["type"] == "mcp_call_log"
        assert received_payloads[1]["data"]["server_name"] == "code-analysis"

    finally:
        await event_bus.disconnect(mock_ws)

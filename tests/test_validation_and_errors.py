"""
Tests for Input Validation, Error Handling & Security Sandboxing
"""

import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app


@pytest.mark.asyncio
async def test_invalid_hash_validation():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Invalid hash: not 0x prefixed or wrong length
        res = await client.post(
            "/api/anchor",
            json={"scan_id": "SCAN-001", "report_hash": "not_a_valid_hash", "network": "anvil"},
        )
        assert res.status_code == 400
        data = res.json()
        assert data["error"] == "InvalidInputError"
        assert "Invalid report hash" in data["detail"]


@pytest.mark.asyncio
async def test_sandbox_path_traversal_rejection():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Attempt path traversal escape
        res = await client.post(
            "/api/scan/start",
            json={"folder_path": "../../Windows/System32"},
        )
        assert res.status_code == 403
        data = res.json()
        assert data["error"] == "SecuritySandboxViolation"
        assert "Security Sandbox Violation" in data["detail"]


@pytest.mark.asyncio
async def test_non_existent_report_404():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/report/NON_EXISTENT_ID/json")
        assert res.status_code == 404

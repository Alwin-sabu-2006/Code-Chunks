"""
Tests for FastAPI Backend Endpoints
"""

import asyncio
import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app


@pytest.mark.asyncio
async def test_health_and_status():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

        res_status = await client.get("/api/system/status")
        assert res_status.status_code == 200
        assert res_status.json()["runs_locally"] is True


@pytest.mark.asyncio
async def test_scan_lifecycle_and_anchoring():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Start scan
        start_res = await client.post("/api/scan/start", json={"sample_app_id": "token_wallet"})
        assert start_res.status_code == 200
        scan_id = start_res.json()["scan_id"]
        assert scan_id.startswith("SCAN-")

        # 2. Allow pipeline to complete
        await asyncio.sleep(1.8)

        # 3. Check status
        status_res = await client.get(f"/api/scan/{scan_id}/status")
        assert status_res.status_code == 200
        assert status_res.json()["status"] == "completed"
        assert status_res.json()["progress_percentage"] == 100

        # 4. Fetch full report
        report_res = await client.get(f"/api/scan/{scan_id}/results")
        assert report_res.status_code == 200
        report_data = report_res.json()
        assert "canonical_hash" in report_data
        report_hash = report_data["canonical_hash"]
        assert report_hash.startswith("0x")

        # 5. Anchor report on chain
        anchor_res = await client.post(
            "/api/anchor",
            json={"scan_id": scan_id, "report_hash": report_hash, "network": "anvil"},
        )
        assert anchor_res.status_code == 200
        record = anchor_res.json()
        assert record["status"] == "anchored"
        assert record["tx_hash"].startswith("0x")

        # 6. Verify hash lookup
        verify_res = await client.get(f"/api/anchor/verify/{report_hash}")
        assert verify_res.status_code == 200
        assert verify_res.json()["match_status"] == "MATCH"
        assert verify_res.json()["is_anchored"] is True

        # 7. Download canonical JSON
        json_res = await client.get(f"/api/report/{scan_id}/json")
        assert json_res.status_code == 200
        canonical_str = json_res.text
        assert "findings" in canonical_str

        # 8. Download PDF
        pdf_res = await client.get(f"/api/report/{scan_id}/pdf")
        assert pdf_res.status_code == 200
        assert pdf_res.headers["content-type"] == "application/pdf"
        assert pdf_res.content.startswith(b"%PDF")

        # 9. Test tamper-check verification with 1 altered character
        tampered_json = canonical_str.replace("token_wallet", "tampered_wallet")
        tamper_res = await client.post(
            "/api/anchor/verify/tamper-check",
            json={"report_hash": report_hash, "canonical_json": tampered_json},
        )
        assert tamper_res.status_code == 200
        assert tamper_res.json()["match_status"] == "TAMPERED"

        # 10. Test simulate-tamper demo endpoint
        sim_res = await client.post(
            "/api/anchor/simulate-tamper",
            json={"canonical_json": canonical_str},
        )
        assert sim_res.status_code == 200
        sim_data = sim_res.json()
        assert sim_data["original_hash"] == report_hash
        assert sim_data["tampered_hash"] != report_hash
        assert sim_data["original_char"] != sim_data["altered_char"]


@pytest.mark.asyncio
async def test_frontend_and_root_aliases():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test /api/health
        h_res = await client.get("/api/health")
        assert h_res.status_code == 200

        # Test POST /api/scan with form data
        scan_res = await client.post("/api/scan", data={"app_id": "token-wallet"})
        assert scan_res.status_code == 200
        scan_json = scan_res.json()
        assert scan_json["status"] == "queued"
        assert "scan_id" in scan_json
        s_id = scan_json["scan_id"]

        # Test GET /api/report/{id}
        rep_res = await client.get(f"/api/report/{s_id}")
        assert rep_res.status_code == 200

        # Test root POST /anchor
        test_hash = "0x" + "a" * 64
        anc_res = await client.post("/anchor", json={"hash": test_hash})
        assert anc_res.status_code == 200
        assert anc_res.json()["success"] is True
        assert anc_res.json()["canonicalHash"] == test_hash

        # Test root GET /verify/{hash}
        ver_res = await client.get(f"/verify/{test_hash}")
        assert ver_res.status_code == 200
        assert ver_res.json()["match"] is True
        assert ver_res.json()["status"] == "MATCH"

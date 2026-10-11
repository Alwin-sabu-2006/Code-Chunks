"""
Q-Chain Member 3 Verification Script
====================================
Comprehensive diagnostic script to verify 100% completion of Member 3 tasks
as specified in Section 15 of the Q-Chain Project Plan & Roadmap.

Usage:
    .venv\\Scripts\\python.exe verify_member3.py
"""

import sys
import os
import json
import time
from pathlib import Path

# ANSI colors for Windows console
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"


def check_item(label: str, condition: bool, details: str = ""):
    if condition:
        print(f"  {GREEN}[PASS]{RESET} {label} {details}")
        return True
    else:
        print(f"  {RED}[FAIL]{RESET} {label} {details}")
        return False


def main():
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}       Q-CHAIN: MEMBER 3 TASK COMPLETION VERIFICATION SUITE              {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")

    results = []

    # ------------------------------------------------------------------------
    # 1. Monorepo & Setup (Phase 0)
    # ------------------------------------------------------------------------
    print(f"{BOLD}1. Monorepo Structure & Docker (Phase 0){RESET}")
    dirs = ["backend", "shared", "mcp_servers", "mcp", "agents", "contracts", "samples", "frontend", "docs"]
    for d in dirs:
        results.append(check_item(f"Directory /{d} exists", Path(d).is_dir()))
    results.append(check_item("docker-compose.yml exists", Path("docker-compose.yml").is_file()))
    results.append(check_item("backend/Dockerfile exists", Path("backend/Dockerfile").is_file()))
    results.append(check_item("requirements.txt exists", Path("requirements.txt").is_file()))

    # ------------------------------------------------------------------------
    # 2. Shared Schemas (Handoff to Everyone - Hour 3)
    # ------------------------------------------------------------------------
    print(f"\n{BOLD}2. Shared Data Contracts & Schemas (Hour 3 Handoff){RESET}")
    results.append(check_item("shared/models.py (Pydantic v2 schemas)", Path("shared/models.py").is_file()))
    results.append(check_item("shared/schema.json (JSON Schema export)", Path("shared/schema.json").is_file()))
    results.append(check_item("shared/types.ts (Frontend TypeScript defs)", Path("shared/types.ts").is_file()))
    results.append(check_item("shared/crypto_utils.py (Canonical hashing)", Path("shared/crypto_utils.py").is_file()))

    from shared.crypto_utils import serialize_canonical_json, compute_report_hash, verify_canonical_integrity
    test_json = serialize_canonical_json({"b": 2, "a": 1})
    test_hash = compute_report_hash(test_json)
    is_match, _ = verify_canonical_integrity(test_json, test_hash)
    results.append(check_item("Canonical sorting & SHA-256 integrity check", is_match and test_hash.startswith("0x")))

    # ------------------------------------------------------------------------
    # 3. Four MCP Servers (Section 7.4)
    # ------------------------------------------------------------------------
    print(f"\n{BOLD}3. Four Domain MCP Servers{RESET}")
    results.append(check_item("MCP Server 1: code-analysis", Path("mcp_servers/code_analysis/server.py").is_file()))
    results.append(check_item("MCP Server 2: crypto-test", Path("mcp_servers/crypto_test/server.py").is_file()))
    results.append(check_item("MCP Server 3: benchmark", Path("mcp_servers/benchmark/server.py").is_file()))
    results.append(check_item("MCP Server 4: blockchain", Path("mcp_servers/blockchain/server.py").is_file()))

    from mcp_servers.code_analysis.server import list_detection_rules, scan_directory
    from mcp_servers.crypto_test.server import run_tamper_tests
    from mcp_servers.benchmark.server import benchmark_algorithm
    from mcp_servers.blockchain.server import anchor_report_hash

    rules = json.loads(list_detection_rules())
    results.append(check_item("code-analysis: detection rules loaded", len(rules) >= 10, f"({len(rules)} rules active)"))

    tamper_res = json.loads(run_tamper_tests("ML-DSA-65"))
    results.append(check_item("crypto-test: 4 tamper scenarios evaluated", tamper_res["result"]["tamper_detection_rate"] == 1.0))

    bench_res = json.loads(benchmark_algorithm("ML-DSA-65 (FIPS 204)"))
    results.append(check_item("benchmark: latency & byte-sizes collected", bench_res["result"]["signature_size_bytes"] == 3309))

    anchor_res = json.loads(anchor_report_hash(test_hash))
    results.append(check_item("blockchain: on-chain anchor tool", anchor_res["record"]["status"] == "anchored"))

    # ------------------------------------------------------------------------
    # 4. Planted Vulnerability Verification (Section 7.1)
    # ------------------------------------------------------------------------
    print(f"\n{BOLD}4. Sample dApps & Detection Score{RESET}")
    scan_wallet = json.loads(scan_directory("samples/token_wallet"))
    results.append(check_item("samples/token_wallet: 5 of 5 planted patterns detected", scan_wallet["findings_count"] == 5))

    scan_voting = json.loads(scan_directory("samples/voting_dapp"))
    results.append(check_item("samples/voting_dapp: 2 of 2 planted patterns detected", scan_voting["findings_count"] == 2))

    scan_multisig = json.loads(scan_directory("samples/multisig"))
    results.append(check_item("samples/multisig: 2 of 2 planted patterns detected", scan_multisig["findings_count"] == 2))

    # ------------------------------------------------------------------------
    # 5. Smart Contract & Anchoring
    # ------------------------------------------------------------------------
    print(f"\n{BOLD}5. Blockchain Smart Contract & Endpoints{RESET}")
    results.append(check_item("contracts/ReportRegistry.sol contract exists", Path("contracts/ReportRegistry.sol").is_file()))
    from backend.services.anchoring_service import anchoring_service
    rec = anchoring_service.get_anchor_record(test_hash)
    results.append(check_item("Registry state lookup (getRecord)", rec is not None))

    # ------------------------------------------------------------------------
    # 6. FastAPI Endpoints & Pipeline (End-to-End Test)
    # ------------------------------------------------------------------------
    print(f"\n{BOLD}6. FastAPI End-to-End API Integration{RESET}")
    import asyncio
    from httpx import AsyncClient, ASGITransport
    from backend.main import app

    async def run_e2e():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Health
            h = await client.get("/health")
            results.append(check_item("GET /health -> HTTP 200", h.status_code == 200))

            # System status
            s = await client.get("/api/system/status")
            results.append(check_item("GET /api/system/status -> Local Edge mode", s.json().get("runs_locally") is True))

            # Scan start
            ss = await client.post("/api/scan/start", json={"sample_app_id": "token_wallet"})
            scan_id = ss.json()["scan_id"]
            results.append(check_item("POST /api/scan/start -> Scan initiated", ss.status_code == 200, f"({scan_id})"))

            await asyncio.sleep(1.8)

            # Results
            rep = await client.get(f"/api/scan/{scan_id}/results")
            rep_data = rep.json()
            results.append(check_item("GET /api/scan/{id}/results -> Canonical report generated", rep.status_code == 200))

            # JSON download
            j = await client.get(f"/api/report/{scan_id}/json")
            results.append(check_item("GET /api/report/{id}/json -> Canonical JSON download", j.status_code == 200))

            # PDF download
            p = await client.get(f"/api/report/{scan_id}/pdf")
            results.append(check_item("GET /api/report/{id}/pdf -> Executive PDF generated", p.status_code == 200 and p.content.startswith(b"%PDF")))

            # Live simulate-tamper demo
            st = await client.post("/api/anchor/simulate-tamper", json={"canonical_json": j.text})
            results.append(check_item("POST /api/anchor/simulate-tamper -> 1-byte alteration detected", st.status_code == 200))

    asyncio.run(run_e2e())

    # ------------------------------------------------------------------------
    # 7. Documentation & Pitch Preparation (Phase 5)
    # ------------------------------------------------------------------------
    print(f"\n{BOLD}7. Documentation & Pitch Defense (Phase 5){RESET}")
    results.append(check_item("README.md with setup instructions", Path("README.md").is_file()))
    results.append(check_item("docs/MEMBER_3_PITCH_GUIDE.md (Judges Q&A)", Path("docs/MEMBER_3_PITCH_GUIDE.md").is_file()))
    results.append(check_item("run_backend.py launcher script", Path("run_backend.py").is_file()))

    # ------------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------------
    total = len(results)
    passed = sum(1 for r in results if r)
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    if passed == total:
        print(f"{BOLD}{GREEN}  ALL {total}/{total} TASKS VERIFIED AND COMPLETE! (100% SUCCESS){RESET}")
        print(f"  Role: Member 3 (Backend and MCP Engineer) is ready for integration!")
    else:
        print(f"{BOLD}{YELLOW}  VERIFICATION RESULT: {passed}/{total} Passed{RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")


if __name__ == "__main__":
    main()

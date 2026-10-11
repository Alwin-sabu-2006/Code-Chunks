# Q-Chain: AI-Assisted Quantum-Safe Migration Platform

> Built for the **Security (Blockchain & Cryptography)** track.  
> Role: **Member 3 — Backend and MCP Engineer**

---

## Architecture Overview

Q-Chain scans blockchain codebases for classical elliptic curve signatures (ECDSA `secp256k1`, `ecrecover`), benchmarks post-quantum alternatives (NIST FIPS 204 `ML-DSA`, `Falcon-512`, FIPS 205 `SLH-DSA`), executes tamper tests, and anchors a canonical report hash onto an EVM blockchain for immutable integrity verification.

```
[ Frontend Dashboard ] <--- WebSocket / REST ---> [ FastAPI Backend ]
  (Next.js / React)                                   |
                                                      v
                                            [ Pipeline Coordinator ]
                                                      |
    +-------------------+--------------------+--------+-----------+
    |                   |                    |                    |
    v                   v                    v                    v
[MCP: code-analysis] [MCP: crypto-test]  [MCP: benchmark]  [MCP: blockchain]
 (Path Sandboxed)     (4 Tamper Tests)     (Timing/Sizes)     (Anvil/EVM)
```

---

## Monorepo Layout

```
├── backend/            # FastAPI REST & WebSocket server, report & PDF generation
│   ├── routers/        # /health, /api/scan, /ws/events, /api/anchor, /api/report
│   ├── services/       # EventBus, PipelineCoordinator, AnchoringService, PDFGenerator
│   └── Dockerfile      # Backend container definition
├── shared/             # The Single Source of Truth for all team members
│   ├── models.py       # Pydantic v2 schemas (Finding, BenchmarkResult, Report, etc.)
│   ├── crypto_utils.py # Deterministic canonical JSON serializer & SHA-256 hasher
│   ├── schema.json     # Generated standard JSON Schema
│   └── types.ts        # TypeScript interface definitions for Member 5 (Frontend)
├── mcp_servers/        # Official Model Context Protocol (MCP) server implementations
│   ├── code_analysis/  # Static scanner with sandbox path allow-listing
│   ├── crypto_test/    # 4-scenario tamper-resistance suite
│   ├── benchmark/      # Nanosecond precision timing & size measurement harness
│   └── blockchain/     # Smart contract anchoring & tamper lookup tools
├── mcp/                # MCP server entrypoints
├── tests/              # Pytest test suite (100% passing across API, MCP & Schemas)
├── docker-compose.yml  # Orchestrates backend, frontend, local Anvil chain & Ollama
└── requirements.txt    # Python 3.11+ dependencies
```

---

## Quickstart

### 1. Local Python Environment
```bash
# Activate virtual environment
.venv\Scripts\activate   # Windows
# or: source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the backend server
python -m backend.main
```
The backend starts at `http://localhost:8000`. Swagger documentation is available at `http://localhost:8000/docs`.

### 2. Run Test Suite
```bash
pytest tests
```

### 3. Docker Compose (Full Stack)
```bash
docker compose up --build
```

---

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health check |
| `GET` | `/api/system/status` | Runtime status & supported PQC algorithms |
| `POST` | `/api/scan/start` | Initiates migration assessment pipeline |
| `GET` | `/api/scan/{id}/status` | Real-time progress percentage & active agent |
| `GET` | `/api/scan/{id}/results` | Canonical assessment report |
| `WS` | `/ws/events` | Real-time WebSocket stream for dashboard feed |
| `POST` | `/api/anchor` | Anchors report hash to blockchain |
| `GET` | `/api/anchor/verify/{hash}` | Verifies on-chain anchoring status |
| `POST` | `/api/anchor/verify/tamper-check` | Live tamper detection (detects 1-char edits) |
| `GET` | `/api/report/{id}/json` | Download canonical sorted JSON |
| `GET` | `/api/report/{id}/pdf` | Download formatted executive PDF report |

---

## Handoff Guide for Teammates

* **Member 1 (Crypto Lead):** Use [`shared/models.py`](shared/models.py) (`BenchmarkResult`, `VerificationResult`). Pair with [`mcp_servers/crypto_test`](mcp_servers/crypto_test) and [`mcp_servers/benchmark`](mcp_servers/benchmark).
* **Member 2 (AI Lead):** Subscribe to [`backend/services/event_bus.py`](backend/services/event_bus.py) and emit `AgentEvent` payloads over `AgentEventType`.
* **Member 4 (Blockchain Lead):** Contract anchoring endpoints are live at `/api/anchor` and connect to [`mcp_servers/blockchain`](mcp_servers/blockchain).
* **Member 5 (Frontend Lead):** Drop [`shared/types.ts`](shared/types.ts) directly into your React/Next.js dashboard. Connect your live activity feed to `ws://localhost:8000/ws/events`.

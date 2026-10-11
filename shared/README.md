# Q-Chain Shared Data Schemas

**Owner:** Member 3 (Backend and MCP Engineer)  
**Consumers:** 
- Member 1 (Crypto & PQC Lead)
- Member 2 (AI & Agents Lead)
- Member 4 (Blockchain & Scanner Lead)
- Member 5 (Frontend, Voice & Demo Lead)

---

## Overview

This directory defines the single source of truth for all data structures exchanged across the Q-Chain platform:

1. **Python Pydantic Models**: [`models.py`](models.py)
2. **Canonical Cryptographic Utils**: [`crypto_utils.py`](crypto_utils.py)
3. **Full JSON Schema**: [`schema.json`](schema.json)
4. **TypeScript Interface Definitions**: [`types.ts`](types.ts)

---

## Core Models

### 1. `Finding`
Produced by: **Member 4 (Code Scanner)** via `code-analysis` MCP server.  
Consumed by: **Member 2 (Decision Agent)**, **Member 5 (Dashboard UI)**.
* `id`: Unique identifier (e.g., `"FIND-001"`).
* `file`: Relative file path.
* `line`: Line number of vulnerable primitive.
* `algorithm`: Detected primitive (`"secp256k1"`, `"ECDSA"`, `"ecrecover"`, `"signMessage"`, etc.).
* `context`: `"key_generation"`, `"signing"`, `"verification"`, `"hash_and_sign"`, or `"general"`.
* `quantum_risk`: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`.
* `confidence`: Float `0.0` to `1.0`.
* `code_snippet`: Verbatim vulnerable line / code snippet.
* `explanation`: Plain-language explanation (Ollama LLM or deterministic fallback).
* `suggested_replacement`: e.g., `"ML-DSA-65"`, `"Falcon-512"`, `"SLH-DSA"`.

---

### 2. `BenchmarkResult`
Produced by: **Member 1 (PQC Lead)** via `benchmark` MCP server.  
Consumed by: **Member 2 (Decision Agent)**, **Member 5 (Benchmark Charts)**.
* `algorithm`: e.g. `"ECDSA_secp256k1"`, `"ML-DSA-65"`, `"Falcon-512"`, `"SLH-DSA"`.
* `category`: `"classical"` or `"post_quantum"`.
* `keygen_metrics`, `sign_metrics`, `verify_metrics`: Contain `mean_ns`, `std_dev_ns`, `iterations`.
* `public_key_size_bytes`: e.g. 33/65 (ECDSA), 1952 (ML-DSA-65), 897 (Falcon-512).
* `signature_size_bytes`: e.g. 64 (ECDSA), 3309 (ML-DSA-65), 666 (Falcon-512), 17088 (SLH-DSA).
* `storage_overhead_ratio`: Ratio compared to ECDSA baseline (64 bytes).

---

### 3. `VerificationResult`
Produced by: **Member 1 (PQC Lead)** via `crypto-test` MCP server.  
Consumed by: **Member 5 (Verification Matrix UI)**.
Evaluates the 4 required tamper scenarios:
1. `valid_signature`: Must pass.
2. `flipped_bit_message`: Must fail.
3. `flipped_bit_signature`: Must fail.
4. `wrong_public_key`: Must fail.
* `tamper_detection_rate`: Expecting `1.0` (100%).

---

### 4. `DecisionResult`
Produced by: **Member 2 (AI Lead / Decision Engine)**.  
* `ranked_findings`: Sorted by risk level.
* `overall_risk_score`: 0–100 score.
* `recommended_algorithm`: e.g., `"ML-DSA-65"` or `"Falcon-512"`.
* `recommendation_rationale`: Gas vs signature size vs speed tradeoff rationale.
* `decision_latency_ms`: In-process triage latency (must be displayed on dashboard, target < 50ms).

---

### 5. `Report`
Assembled by: **Member 3 (Backend Engineer)**.  
Anchored by: **Member 4 (Blockchain Engineer)**.  
* Aggregates findings, benchmarks, verification matrix, decision, tool versions.
* `canonical_hash`: SHA-256 / Keccak-256 of sorted canonical JSON.
* `anchor_record`: On-chain transaction receipt.

---

### 6. `AgentEvent` & `McpCallLog`
Emitted over WebSocket (`ws://localhost:8000/ws/events`) in real time to drive the UI live activity feed and MCP log panel.

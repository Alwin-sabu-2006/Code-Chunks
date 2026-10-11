# Q-Chain: Member 3 Pitch & Architecture Defense Guide

> **Your Role in the Pitch:** Architecture, System Design & MCP Lead  
> **Target Audience:** Hackathon Judges (Blockchain, Cryptography & Systems Track)

---

## 1. System Architecture Overview

```
[ Web Dashboard ] <=== WebSocket / REST ===> [ FastAPI Backend (Member 3) ]
 (Next.js/React)                                      |
                                                      v
                                           [ Pipeline Coordinator ]
                                                      |
                   +-------------------+--------------+----+-------------------+
                   |                   |                   |                   |
                   v                   v                   v                   v
           [ Analysis Agent ]   [ PQC Test Agent ]  [ Verification Agent ] [ Report Agent ]
                   |                   |                   |                   |
                   +=================== MCP Client Protocol ===================+
                                       |
    +-------------------+--------------+----+-------------------+
    |                   |                   |                   |
    v                   v                   v                   v
[MCP: code-analysis] [MCP: crypto-test] [MCP: benchmark]    [MCP: blockchain]
 - Sandboxed Paths    - 4 Tamper Tests   - 100+ Iterations   - Anvil EVM State
 - 20+ RegEx Rules    - 100% Detection   - Gas/Size Matrix   - Canonical SHA-256
```

---

## 2. Prepared Answers for Judges' Tough Questions

### Q1: "Why did you build this on the Model Context Protocol (MCP) instead of standard Python functions or LangChain tools?"
> **Your Answer:**  
> "MCP provides a clean architectural boundary between **agent decision logic** and **security tool execution**.  
> By isolating our four domains (`code-analysis`, `crypto-test`, `benchmark`, and `blockchain`) into dedicated MCP servers, we gain three critical benefits:
> 1. **Zero Privilege Creep:** The AI agents cannot execute arbitrary bash commands or access files outside the sandboxed project path.
> 2. **Auditable Telemetry:** Every single tool call, duration, argument, and output is captured as a structured `McpCallLog` and streamed live to the UI.
> 3. **Interoperability:** Any MCP-compliant client (Claude Desktop, custom orchestrators, or local edge models) can plug into our crypto engine without rewriting backend code."

---

### Q2: "How do you prevent hallucinations in security assessments?"
> **Your Answer:**  
> "By strict adherence to Rule #1 in our architecture: **Deterministic tools do the work; the LLM only explains.**  
> - Pattern detection is handled by our deterministic regex engine.
> - Benchmarks are measured by nanosecond CPU timing harnesses with 100+ warm-up iterations.
> - Tamper resistance is proven by bit-flip assertions.
> - Triage ranking uses deterministic System One scoring rules.
> The local LLM translates technical findings into plain English, but it **never decides a security outcome or modifies the ranking**."

---

### Q3: "What is your on-chain trust model? Isn't anchoring classical signatures flawed if quantum computers arrive?"
> *(The Mandatory Scope Statement from the Team Plan)*  
> **Your Answer:**  
> "We are very candid about our scope: **Q-Chain assesses and verifies migration readiness.**  
> It does not claim that off-chain PQC signatures make existing on-chain transaction authorization quantum-safe today.  
> On-chain anchoring **proves report integrity and chronological timestamping**—proving that this exact codebase was audited at this block time and has not been altered by a single byte since.  
> The anchoring transaction itself still relies on the host chain's classical signatures until EVM chains deploy native PQC precompiles."

---

### Q4: "How does your live tamper detection work during the demo?"
> **Your Answer:**  
> "Our report serialization produces **Canonical JSON**: keys are sorted recursively, with exact zero-whitespace formatting.  
> We hash this canonical string with SHA-256 and commit the 32-byte digest on-chain.  
> In our demo, clicking 'Simulate Tamper' alters **just one character** in the report. Because SHA-256 has strict avalanche effect, the recomputed hash diverges entirely, and our smart contract verifier instantly flags it as **TAMPERED**."

---

## 3. Demo Flow Checklist (Member 3 Coordinates)

| Minute | Stage | What Judges See |
| :--- | :--- | :--- |
| **0:20 - 0:50** | **Scan Starts** | Frontend triggers `POST /api/scan/start`. WebSocket feed shows `AgentEvent` and `McpCallLog` entries scrolling by with latency counters. |
| **0:50 - 1:20** | **Findings** | 5 planted findings detected in `samples/token_wallet` (100% detection rate). Decision engine finishes in **< 10ms**. |
| **1:20 - 2:00** | **Benchmarks** | PQC vs ECDSA bar charts for signature sizes (Falcon: 666B, ML-DSA: 3309B) and verify times. |
| **2:00 - 2:20** | **Verification** | Tamper matrix shows 4/4 green passes (100% tamper detection). |
| **2:20 - 2:50** | **Anchoring** | Report hash anchored on chain. Click 'Simulate Tamper' -> immediate red **TAMPERED** alert! |
| **2:50 - 3:00** | **Close** | State scope limitation cleanly and deliver pitch conclusion. |

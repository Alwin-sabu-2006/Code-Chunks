"""
Q-Chain Shared Data Models
==========================
Defines typed schemas for the Q-Chain Post-Quantum Migration Platform.
Used across FastAPI Backend, Multi-Agent Orchestrator, MCP Servers, and Frontend.

Owner: Member 3 (Backend and MCP Engineer)
Team: Q-Chain (Members 1, 2, 3, 4, 5)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# Enums
# ============================================================================

class QuantumRiskLevel(str, Enum):
    CRITICAL = "CRITICAL"  # e.g., On-chain auth or key storage using raw secp256k1
    HIGH = "HIGH"          # Classical signature scheme (ECDSA/RSA/ed25519)
    MEDIUM = "MEDIUM"      # Classical hashing or auxiliary key exchange
    LOW = "LOW"            # Symmetric crypto with sufficient key length (AES-256)


class CryptoContext(str, Enum):
    KEY_GENERATION = "key_generation"
    SIGNING = "signing"
    VERIFICATION = "verification"
    HASH_AND_SIGN = "hash_and_sign"
    GENERAL = "general"


class AlgorithmCategory(str, Enum):
    CLASSICAL = "classical"
    POST_QUANTUM = "post_quantum"
    HYBRID = "hybrid"


class AgentEventType(str, Enum):
    AGENT_STARTED = "agent_started"
    TOOL_CALLED = "tool_called"
    TOOL_COMPLETED = "tool_completed"
    AGENT_FINISHED = "agent_finished"
    DECISION_MADE = "decision_made"
    ERROR = "error"
    LOG = "log"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    SCANNING = "scanning"
    BENCHMARKING = "benchmarking"
    VERIFYING = "verifying"
    DECIDING = "deciding"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class TamperScenarioType(str, Enum):
    VALID_SIGNATURE = "valid_signature"
    FLIPPED_BIT_MESSAGE = "flipped_bit_message"
    FLIPPED_BIT_SIGNATURE = "flipped_bit_signature"
    WRONG_PUBLIC_KEY = "wrong_public_key"


# ============================================================================
# 1. Finding Schema (Code Scanner / Cryptographic Analysis)
# ============================================================================

class Finding(BaseModel):
    """Represents a vulnerable cryptographic pattern detected in codebase."""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Unique finding identifier (e.g. FIND-001)")
    file: str = Field(..., description="Relative file path where pattern was discovered")
    line: int = Field(..., description="Line number of detected code")
    algorithm: str = Field(..., description="Detected classical algorithm, e.g. secp256k1, ECDSA, ecrecover")
    context: CryptoContext = Field(..., description="Context of usage: keygen, signing, verification")
    quantum_risk: QuantumRiskLevel = Field(..., description="Severity level of vulnerability")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence score between 0.0 and 1.0")
    code_snippet: str = Field(..., description="Code snippet containing the vulnerability")
    explanation: Optional[str] = Field(None, description="Plain-language explanation from LLM or deterministic fallback")
    suggested_replacement: Optional[str] = Field(None, description="Recommended PQC replacement (e.g. ML-DSA-65, Falcon-512)")


# ============================================================================
# 2. Benchmark Result Schema (PQC Testing Harness)
# ============================================================================

class BenchmarkMetrics(BaseModel):
    """Timing metrics collected from benchmark runs."""
    model_config = ConfigDict(extra="ignore")

    mean_ns: float = Field(..., description="Mean execution duration in nanoseconds")
    std_dev_ns: float = Field(0.0, description="Standard deviation in nanoseconds")
    iterations: int = Field(100, description="Sample count / iterations run")
    mean_us: Optional[float] = Field(None, description="Mean duration in microseconds (convenience)")

    def model_post_init(self, __context: Any) -> None:
        if self.mean_us is None:
            self.mean_us = round(self.mean_ns / 1000.0, 3)


class BenchmarkResult(BaseModel):
    """Performance & size benchmarks comparing Classical vs PQC algorithms."""
    model_config = ConfigDict(extra="ignore")

    algorithm: str = Field(..., description="Name of algorithm (e.g. ECDSA_secp256k1, ML-DSA-65, Falcon-512, SLH-DSA)")
    category: AlgorithmCategory = Field(..., description="classical or post_quantum")
    public_key_size_bytes: int = Field(..., description="Public key size in bytes")
    signature_size_bytes: int = Field(..., description="Signature size in bytes")
    message_size_bytes: int = Field(32, description="Message size used during benchmark")
    keygen_metrics: BenchmarkMetrics = Field(..., description="Key generation latency")
    sign_metrics: BenchmarkMetrics = Field(..., description="Signing latency")
    verify_metrics: BenchmarkMetrics = Field(..., description="Verification latency")
    estimated_onchain_gas: Optional[int] = Field(None, description="Estimated on-chain gas cost or relative multiplier")
    storage_overhead_ratio: Optional[float] = Field(None, description="Signature size ratio relative to ECDSA (64 bytes)")


# ============================================================================
# 3. Verification Result Schema (Tamper Matrix)
# ============================================================================

class TamperScenarioResult(BaseModel):
    """Single tamper scenario verification outcome."""
    model_config = ConfigDict(extra="ignore")

    scenario: TamperScenarioType = Field(..., description="Tamper test scenario")
    description: str = Field(..., description="Description of the test conducted")
    expected_pass: bool = Field(..., description="Whether this scenario is expected to pass verification")
    actual_pass: bool = Field(..., description="Whether verification succeeded")
    test_passed: bool = Field(..., description="True if actual_pass matches expected_pass")
    details: Optional[str] = Field(None, description="Diagnostic details")


class VerificationResult(BaseModel):
    """Verification and tamper-resistance test outcomes for an algorithm."""
    model_config = ConfigDict(extra="ignore")

    algorithm: str = Field(..., description="Algorithm name tested")
    scenarios: List[TamperScenarioResult] = Field(..., description="List of 4 tamper scenarios")
    tamper_detection_rate: float = Field(1.0, ge=0.0, le=1.0, description="Detection rate (1.0 = 100%)")
    all_tests_passed: bool = Field(True, description="True if all tamper and valid tests behaved as expected")


# ============================================================================
# 4. Decision Engine Result Schema (System One Layer)
# ============================================================================

class DecisionResult(BaseModel):
    """Outcome produced by the System One triage & recommendation engine."""
    model_config = ConfigDict(extra="ignore")

    ranked_findings: List[Finding] = Field(default_factory=list, description="Findings ordered by priority/risk")
    overall_risk_score: float = Field(..., ge=0.0, le=100.0, description="Aggregated risk score (0-100)")
    recommended_algorithm: str = Field(..., description="Recommended PQC algorithm (e.g. ML-DSA-65 or Falcon-512)")
    recommendation_rationale: str = Field(..., description="Justification based on speed, gas, and signature size constraints")
    decision_latency_ms: float = Field(..., description="Engine execution latency in milliseconds (target < 50ms)")
    rules_applied: List[str] = Field(default_factory=list, description="Decision rules triggered during triage")
    scan_outcome: str = Field("QUANTUM_SAFE", description="Outcome: FINDINGS_DETECTED, QUANTUM_SAFE, or UNANALYZABLE")
    files_scanned: int = Field(0, description="Total number of code files parsed")
    lines_scanned: int = Field(0, description="Total source lines inspected")
    languages_detected: List[str] = Field(default_factory=list, description="Programming languages detected")


# ============================================================================
# 5. Blockchain Anchoring Schema
# ============================================================================

class AnchorRecord(BaseModel):
    """On-chain anchoring state for a verified report hash."""
    model_config = ConfigDict(extra="ignore")

    report_hash: str = Field(..., description="Deterministic SHA-256 or keccak256 hex string with 0x prefix")
    tx_hash: Optional[str] = Field(None, description="Blockchain transaction hash")
    submitter: Optional[str] = Field(None, description="Ethereum address of submitter")
    timestamp: int = Field(..., description="Unix timestamp of anchoring")
    block_number: Optional[int] = Field(None, description="Block number on target network")
    network: str = Field("anvil", description="Target blockchain: anvil, hardhat, sepolia")
    status: Literal["anchored", "pending", "failed", "unanchored"] = Field("unanchored")


# ============================================================================
# 6. Canonical Report Schema
# ============================================================================

class Report(BaseModel):
    """Full canonical assessment report, signed and anchored on-chain."""
    model_config = ConfigDict(extra="ignore")

    report_id: str = Field(..., description="UUID or identifier of report")
    title: str = Field("Q-Chain Post-Quantum Migration Assessment", description="Report title")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO UTC timestamp")
    target_app_name: str = Field(..., description="Name of scanned application")
    target_app_path: str = Field(..., description="Repository or folder analyzed")
    tool_versions: Dict[str, str] = Field(
        default_factory=lambda: {
            "qchain_core": "1.0.0",
            "liboqs": "0.10.0",
            "python": "3.13",
            "fastapi": "0.115.0"
        },
        description="Versions of all diagnostic engines and compilers"
    )
    findings: List[Finding] = Field(default_factory=list, description="All detected vulnerabilities")
    benchmarks: List[BenchmarkResult] = Field(default_factory=list, description="Performance comparisons")
    verification_matrix: List[VerificationResult] = Field(default_factory=list, description="Tamper test matrix")
    decision: DecisionResult = Field(..., description="Triage ranking & recommendation")
    scan_outcome: Optional[str] = Field("QUANTUM_SAFE", description="Outcome: FINDINGS_DETECTED, QUANTUM_SAFE, or UNANALYZABLE")
    files_scanned: Optional[int] = Field(0, description="Total number of code files parsed")
    lines_scanned: Optional[int] = Field(0, description="Total source lines inspected")
    languages_detected: Optional[List[str]] = Field(default_factory=list, description="Programming languages detected")
    canonical_hash: Optional[str] = Field(None, description="SHA-256 hash of the canonical JSON (computed over sorted payload)")
    anchor_record: Optional[AnchorRecord] = Field(None, description="On-chain anchoring receipt if committed")
    pqc_signature: Optional[str] = Field(None, description="Optional ML-DSA signature of the report hash")
    pqc_public_key: Optional[str] = Field(None, description="Optional ML-DSA public key for report verification")

    def to_canonical_dict(self) -> Dict[str, Any]:
        """
        Returns a dict suitable for canonical JSON generation.
        Omits self-referential fields: canonical_hash, anchor_record, pqc_signature, pqc_public_key.
        """
        raw = self.model_dump(mode="json")
        for key in ["canonical_hash", "anchor_record", "pqc_signature", "pqc_public_key"]:
            raw.pop(key, None)
        return raw

    def to_canonical_json(self) -> str:
        """Serializes dictionary with sorted keys and tight separators to ensure exact byte reproducibility."""
        canonical_dict = self.to_canonical_dict()
        return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))


# ============================================================================
# 7. Agent & MCP Event Stream Schemas (WebSocket UI Feed)
# ============================================================================

class AgentEvent(BaseModel):
    """Real-time event emitted by Orchestrator and Agents over WebSocket."""
    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(..., description="Unique event ID")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_id: str = Field(..., description="Scan session ID")
    agent_name: str = Field(..., description="Name of emitting agent (e.g. AnalysisAgent, PqcTestAgent)")
    event_type: AgentEventType = Field(..., description="Type of event")
    message: str = Field(..., description="Human-readable event message for dashboard feed")
    data: Optional[Dict[str, Any]] = Field(None, description="Structured payload")


class McpCallLog(BaseModel):
    """Detailed record of an MCP tool invocation for the MCP Call Log Panel."""
    model_config = ConfigDict(extra="ignore")

    call_id: str = Field(..., description="Call correlation ID")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_id: Optional[str] = Field(None, description="Associated scan ID")
    server_name: str = Field(..., description="MCP server: code-analysis, crypto-test, benchmark, blockchain")
    tool_name: str = Field(..., description="Invoked tool name")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool input arguments")
    result_summary: Optional[str] = Field(None, description="Concise summary of result")
    duration_ms: float = Field(..., description="Execution duration in milliseconds")
    status: Literal["success", "error"] = Field("success")
    error_message: Optional[str] = Field(None, description="Error text if failed")


# ============================================================================
# 8. API Request & Response Schemas
# ============================================================================

class ScanStartRequest(BaseModel):
    """Payload to trigger a new migration assessment scan."""
    sample_app_id: Optional[str] = Field(None, description="ID of bundled sample: token_wallet, voting_dapp, multisig")
    folder_path: Optional[str] = Field(None, description="Local folder path within allowed sandbox")
    enable_llm_explanations: bool = Field(True, description="Whether to invoke local Ollama LLM for explanations")


class ScanStartResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    target_app_name: str
    created_at: str
    websocket_url: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    progress_percentage: int = Field(0, ge=0, le=100)
    current_agent: Optional[str] = None
    created_at: str
    updated_at: str
    error: Optional[str] = None


class AnchorRequest(BaseModel):
    scan_id: str
    report_hash: str
    network: str = "anvil"


class VerifyHashRequest(BaseModel):
    report_hash: str
    canonical_json: Optional[str] = None


class VerifyHashResponse(BaseModel):
    report_hash: str
    computed_hash: Optional[str] = None
    match_status: Literal["MATCH", "TAMPERED", "NOT_FOUND"] = Field(...)
    is_anchored: bool
    record: Optional[AnchorRecord] = None
    verification_message: str

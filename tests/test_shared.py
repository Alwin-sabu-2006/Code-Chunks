"""
Tests for Shared Models and Canonical Hashing
"""

import json
from shared.models import (
    Finding,
    CryptoContext,
    QuantumRiskLevel,
    BenchmarkMetrics,
    BenchmarkResult,
    AlgorithmCategory,
    TamperScenarioType,
    TamperScenarioResult,
    VerificationResult,
    DecisionResult,
    Report,
    AgentEvent,
    AgentEventType,
    McpCallLog,
)
from shared.crypto_utils import (
    serialize_canonical_json,
    compute_report_hash,
    verify_canonical_integrity,
)


def test_finding_model():
    finding = Finding(
        id="FIND-001",
        file="contracts/Token.sol",
        line=42,
        algorithm="ecrecover",
        context=CryptoContext.VERIFICATION,
        quantum_risk=QuantumRiskLevel.CRITICAL,
        confidence=0.98,
        code_snippet="address signer = ecrecover(hash, v, r, s);",
        explanation="Solidity ecrecover relies on secp256k1 ECDSA, vulnerable to Shor's algorithm.",
        suggested_replacement="ML-DSA-65",
    )
    assert finding.id == "FIND-001"
    assert finding.quantum_risk == QuantumRiskLevel.CRITICAL


def test_canonical_json_and_hashing():
    sample_data = {
        "zebra": 1,
        "apple": 2,
        "nested": {"beta": "b", "alpha": "a"},
    }
    canonical = serialize_canonical_json(sample_data)
    # Check that keys are ordered
    assert canonical == '{"apple":2,"nested":{"alpha":"a","beta":"b"},"zebra":1}'

    report_hash = compute_report_hash(canonical)
    assert report_hash.startswith("0x")
    assert len(report_hash) == 66  # 0x + 64 hex chars

    is_match, comp = verify_canonical_integrity(canonical, report_hash)
    assert is_match is True
    assert comp == report_hash

    # Tampering test: modify one char
    tampered = canonical.replace('"apple":2', '"apple":3')
    is_match_tampered, comp_tampered = verify_canonical_integrity(tampered, report_hash)
    assert is_match_tampered is False
    assert comp_tampered != report_hash


def test_report_canonical_dict():
    decision = DecisionResult(
        ranked_findings=[],
        overall_risk_score=75.5,
        recommended_algorithm="ML-DSA-65",
        recommendation_rationale="Balanced signature size and gas constraints for general smart contract use.",
        decision_latency_ms=12.4,
        rules_applied=["R-SOL-001", "R-REC-002"],
    )

    report = Report(
        report_id="REP-2026-001",
        target_app_name="Sample Token Wallet",
        target_app_path="./samples/token_wallet",
        findings=[],
        benchmarks=[],
        verification_matrix=[],
        decision=decision,
        canonical_hash="0x1234567890abcdef",  # Should be omitted in canonical dict
    )

    canon_dict = report.to_canonical_dict()
    assert "canonical_hash" not in canon_dict
    assert "anchor_record" not in canon_dict

    canon_str = report.to_canonical_json()
    assert "canonical_hash" not in canon_str
    assert report.report_id in canon_str

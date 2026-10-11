"""
Unit Tests for Canonical JSON Hashing and ML-DSA Report Signing.
"""

import pytest
import json
from crypto.report_signer import (
    canonicalize_json,
    compute_report_hashes,
    PQCReportSigner,
)
from schemas.crypto_schemas import SignedReport


def test_canonical_json_determinism():
    dict1 = {"z": 1, "a": 2, "m": {"b": 10, "a": 20}}
    dict2 = {"a": 2, "m": {"a": 20, "b": 10}, "z": 1}

    bytes1 = canonicalize_json(dict1)
    bytes2 = canonicalize_json(dict2)

    assert bytes1 == bytes2
    assert bytes1 == b'{"a":2,"m":{"a":20,"b":10},"z":1}'


def test_report_signing_and_verification():
    report = {
        "assessment_id": "test-assessment-001",
        "scanner": "Q-Chain Analysis Agent v1.0",
        "findings_count": 5,
        "critical_count": 2,
        "pqc_recommendation": "ML-DSA-44",
    }

    signer = PQCReportSigner(variant="ML-DSA-44")
    signed = signer.sign_report(report)

    assert isinstance(signed, SignedReport)
    assert signed.verification_status == "VERIFIED"
    assert signed.signing_algorithm == "ML-DSA-44"
    assert len(signed.canonical_report_hash_sha256) == 64
    assert signed.canonical_report_hash_keccak256.startswith("0x")

    # Verify authentic report
    assert signer.verify_report(report, signed) is True

    # Verify tampered report fails
    tampered = dict(report)
    tampered["findings_count"] = 6
    assert signer.verify_report(tampered, signed) is False

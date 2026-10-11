"""
Tests for all 4 MCP Servers
"""

import json
from mcp_servers.code_analysis.server import list_detection_rules, scan_directory
from mcp_servers.crypto_test.server import run_tamper_tests, verify_signature
from mcp_servers.benchmark.server import benchmark_algorithm, compare_all_algorithms
from mcp_servers.blockchain.server import anchor_report_hash, get_anchor_record, verify_document_integrity


def test_code_analysis_mcp():
    rules_json = list_detection_rules()
    rules = json.loads(rules_json)
    assert len(rules) > 5

    scan_res = scan_directory("shared")
    parsed = json.loads(scan_res)
    assert parsed["status"] == "success"
    assert "findings" in parsed


def test_crypto_test_mcp():
    res_json = run_tamper_tests("ML-DSA-65")
    data = json.loads(res_json)
    assert data["result"]["tamper_detection_rate"] == 1.0
    assert data["result"]["all_tests_passed"] is True
    assert len(data["result"]["scenarios"]) == 4

    sig_verif = json.loads(verify_signature("ML-DSA-65", "msg", "valid_sig", "pk"))
    assert sig_verif["is_valid"] is True


def test_benchmark_mcp():
    single_res = json.loads(benchmark_algorithm("ML-DSA-65 (FIPS 204)", 50))
    assert single_res["result"]["signature_size_bytes"] == 3309
    assert single_res["result"]["public_key_size_bytes"] == 1952
    assert single_res["call_log"]["status"] == "success"

    all_res = json.loads(compare_all_algorithms(20))
    assert len(all_res) == 4


def test_blockchain_mcp():
    test_hash = "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"
    anchor_res = json.loads(anchor_report_hash(test_hash, "anvil"))
    assert anchor_res["record"]["status"] == "anchored"
    assert anchor_res["record"]["report_hash"] == test_hash

    lookup_res = json.loads(get_anchor_record(test_hash))
    assert lookup_res["status"] == "found"

    # Integrity verification with mock canonical JSON
    canonical = '{"app":"test","score":90}'
    from shared.crypto_utils import compute_report_hash
    real_hash = compute_report_hash(canonical)
    _ = anchor_report_hash(real_hash, "anvil")

    match_check = json.loads(verify_document_integrity(real_hash, canonical))
    assert match_check["match_status"] == "MATCH"

    tampered_check = json.loads(verify_document_integrity(real_hash, '{"app":"tampered","score":90}'))
    assert tampered_check["match_status"] == "TAMPERED"

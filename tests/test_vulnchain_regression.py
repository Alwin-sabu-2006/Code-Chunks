"""
VulnChain Regression Test Suite
===============================
Verifies that Q-Chain's code analyzer scores 5/5 on VulnChain (100% recall),
flags 0 decoys (100% precision), and enforces fail-closed behavior on unanalyzable code.

Ground truth per samples/vulnchain/expected_findings.md:
1. wallet.py: ec.SECP256K1(), ec.generate_private_key
2. wallet.py: ec.ECDSA(hashes.SHA256()) sign and verify
3. ledger.py: sender_pub stored in every Transaction
4. node_identity.py: rsa.generate_private_key, RSA PKCS1v15 sign/verify
5. node_identity.py: ec.ECDH() with P-256

Decoys (must NOT be flagged):
- wallet.py: hashlib.sha256 in address_of
- ledger.py: hashlib.sha256 in hash_block
"""

import pytest
from mcp_servers.code_analysis.scanner import CodeScanner
from backend.services.pipeline_coordinator import PipelineCoordinator


def test_vulnchain_returns_exact_five_findings():
    scanner = CodeScanner(allowed_root_path=".")
    findings, duration_ms, log = scanner.scan_directory("samples/vulnchain")

    # 1. Total findings must be exactly 5
    assert len(findings) == 5, f"Expected exactly 5 findings on VulnChain, got {len(findings)}: {[f.code_snippet for f in findings]}"

    # 2. Verify all 5 expected algorithm patterns are detected
    algorithms = {f.algorithm for f in findings}
    assert "ec.SECP256K1" in algorithms, "Missing Finding 1: ec.SECP256K1"
    assert "ec.ECDSA" in algorithms, "Missing Finding 2: ec.ECDSA"
    assert "raw_public_key_exposure" in algorithms, "Missing Finding 3: sender_pub on-chain exposure"
    assert "RSA_2048_PKCS1v15" in algorithms, "Missing Finding 4: RSA PKCS1v15"
    assert "ec.ECDH_P256" in algorithms, "Missing Finding 5: ec.ECDH"

    # 3. Verify finding distributions across files
    by_file = {}
    for f in findings:
        by_file.setdefault(f.file.replace("\\", "/"), []).append(f)

    # wallet.py must have exactly 2 findings
    wallet_findings = [f for path, flist in by_file.items() if "wallet.py" in path for f in flist]
    assert len(wallet_findings) == 2, f"wallet.py should have 2 findings, got {len(wallet_findings)}"

    # ledger.py must have exactly 1 finding
    ledger_findings = [f for path, flist in by_file.items() if "ledger.py" in path for f in flist]
    assert len(ledger_findings) == 1, f"ledger.py should have 1 finding, got {len(ledger_findings)}"

    # node_identity.py must have exactly 2 findings
    node_findings = [f for path, flist in by_file.items() if "node_identity.py" in path for f in flist]
    assert len(node_findings) == 2, f"node_identity.py should have 2 findings, got {len(node_findings)}"

    # 4. Decoy verification: hashlib.sha256 must NEVER be flagged
    for f in findings:
        assert "hashlib.sha256" not in f.code_snippet, f"Decoy hashlib.sha256 was falsely flagged in {f.file} line {f.line}"

    # 5. Non-crypto demo and test files must have 0 findings
    other_findings = [f for path, flist in by_file.items() if any(k in path for k in ["demo.py", "test_vulnchain.py", "app.py"]) for f in flist]
    assert len(other_findings) == 0, f"Found unexpected findings in support files: {[f.code_snippet for f in other_findings]}"

    # 6. Telemetry validation
    telemetry = scanner.last_telemetry
    assert telemetry["files_scanned"] > 0
    assert telemetry["lines_scanned"] > 0
    assert "python" in telemetry["languages_detected"]


def test_scan_single_wallet_py():
    scanner = CodeScanner(allowed_root_path=".")
    findings, duration_ms, _ = scanner.scan_directory("samples/vulnchain/wallet.py")

    assert len(findings) == 2
    algs = {f.algorithm for f in findings}
    assert "ec.SECP256K1" in algs
    assert "ec.ECDSA" in algs


def test_scan_solidity_snippet(tmp_path):
    sol_file = tmp_path / "Snippet.sol"
    sol_file.write_text("address a = ecrecover(h, v, r, s);\n")

    scanner = CodeScanner(allowed_root_path=str(tmp_path))
    findings, _ = scanner.scan_file(str(sol_file))

    assert len(findings) == 1
    assert findings[0].algorithm == "ecrecover_secp256k1"


def test_fail_closed_on_empty_or_unsupported(tmp_path):
    # Directory with only text files (no valid code)
    txt_file = tmp_path / "notes.txt"
    txt_file.write_text("Just some notes with no code.\n")

    coordinator = PipelineCoordinator()
    scanner = CodeScanner(allowed_root_path=str(tmp_path))
    findings, _, _ = scanner.scan_directory(str(tmp_path))

    assert len(findings) == 0
    assert scanner.last_telemetry["files_scanned"] == 0

    # Decision engine must NOT report QUANTUM_SAFE for unanalyzed code
    decision = coordinator._compute_decision(findings, [], scanner.last_telemetry)
    assert decision.scan_outcome == "UNANALYZABLE"
    assert "Could Not Analyze" in decision.recommended_algorithm


def test_scanner_engine_vulnchain_exact_five_findings():
    from scanner.engine import CodeScanner as EngineScanner
    scanner = EngineScanner()
    res = scanner.scan_directory("samples/vulnchain")

    findings = res["findings"]
    assert len(findings) == 5, f"Expected 5 findings, got {len(findings)}: {[f['snippet'] for f in findings]}"
    assert res["scan_outcome"] == "FINDINGS_DETECTED"
    assert res["files_scanned"] == 6
    assert res["lines_scanned"] > 0
    assert "python" in res["languages_detected"]

    # Verify algorithms
    algos = {f["algorithm"] for f in findings}
    assert "ec.SECP256K1" in algos
    assert "ec.ECDSA" in algos
    assert "raw_public_key_exposure" in algos
    assert "RSA_2048_PKCS1v15" in algos
    assert "ec.ECDH_P256" in algos

    # Verify decoys are not flagged
    for f in findings:
        assert "hashlib.sha256" not in f["snippet"]


def test_scanner_engine_single_wallet_py():
    from scanner.engine import CodeScanner as EngineScanner
    scanner = EngineScanner()
    res = scanner.scan_directory("samples/vulnchain/wallet.py")

    assert len(res["findings"]) == 2
    assert res["scan_outcome"] == "FINDINGS_DETECTED"
    assert res["files_scanned"] == 1
    assert "python" in res["languages_detected"]


def test_scanner_engine_solidity_snippet(tmp_path):
    from scanner.engine import CodeScanner as EngineScanner
    sol_file = tmp_path / "Snippet.sol"
    sol_file.write_text("address a = ecrecover(h, v, r, s);\n")

    scanner = EngineScanner()
    res = scanner.scan_directory(str(sol_file))

    assert len(res["findings"]) == 1
    assert res["scan_outcome"] == "FINDINGS_DETECTED"
    assert res["files_scanned"] == 1
    assert res["findings"][0]["algorithm"] == "secp256k1" or "ecrecover" in res["findings"][0]["snippet"]


def test_scanner_engine_fail_closed_on_empty(tmp_path):
    from scanner.engine import CodeScanner as EngineScanner
    txt_file = tmp_path / "notes.txt"
    txt_file.write_text("Unsupported non-code file\n")

    scanner = EngineScanner()
    res = scanner.scan_directory(str(tmp_path))

    assert len(res["findings"]) == 0
    assert res["files_scanned"] == 0
    assert res["scan_outcome"] == "UNANALYZABLE"


def test_scan_zip_archives(tmp_path):
    import zipfile
    from scanner.engine import CodeScanner as EngineScanner

    # Create test zip containing vulnchain wallet.py and ledger.py
    zip_path = tmp_path / "test_app.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write("samples/vulnchain/wallet.py", "wallet.py")
        zf.write("samples/vulnchain/ledger.py", "ledger.py")

    # Test EngineScanner scan_zip
    engine = EngineScanner()
    res_engine = engine.scan_zip(str(zip_path), str(tmp_path / "engine_extracted"))
    assert len(res_engine["findings"]) == 3  # 2 in wallet, 1 in ledger
    assert res_engine["scan_outcome"] == "FINDINGS_DETECTED"
    assert res_engine["files_scanned"] == 2

    # Test MCP CodeScanner scan_zip
    mcp_scanner = CodeScanner(allowed_root_path=str(tmp_path))
    findings_mcp, _, _ = mcp_scanner.scan_zip(str(zip_path), str(tmp_path / "mcp_extracted"))
    assert len(findings_mcp) == 3
    assert mcp_scanner.last_telemetry["files_scanned"] == 2

"""
Tests for Detection Score on Documented Planted Samples
Verifies 100% detection rate across all 3 bundled sample apps.
"""

from mcp_servers.code_analysis.scanner import CodeScanner


def test_token_wallet_detection():
    scanner = CodeScanner(allowed_root_path=".")
    findings, duration_ms, log = scanner.scan_directory("samples/token_wallet")

    assert len(findings) == 5
    algorithms = {f.algorithm for f in findings}
    assert "ecrecover_secp256k1" in algorithms
    assert "ethers_Wallet_secp256k1" in algorithms
    assert "secp256k1_signMessage" in algorithms
    assert "eth_account_ECDSA" in algorithms
    assert log.status == "success"


def test_voting_dapp_detection():
    scanner = CodeScanner(allowed_root_path=".")
    findings, duration_ms, log = scanner.scan_directory("samples/voting_dapp")

    assert len(findings) == 2
    algorithms = {f.algorithm for f in findings}
    assert "ecrecover_secp256k1" in algorithms
    assert "web3_account_ECDSA" in algorithms


def test_multisig_detection():
    scanner = CodeScanner(allowed_root_path=".")
    findings, duration_ms, log = scanner.scan_directory("samples/multisig")

    assert len(findings) == 2
    algorithms = {f.algorithm for f in findings}
    assert "ecrecover_secp256k1" in algorithms
    assert "ed25519_Edwards_Curve" in algorithms

"""
Tests for Code Analysis MCP Server and Scanner
"""

import pytest
from pathlib import Path
from mcp_servers.code_analysis.scanner import CodeScanner
from mcp_servers.code_analysis.rules import RULES


def test_code_scanner_detects_patterns(tmp_path):
    # Create sample vulnerable Solidity contract
    sol_file = tmp_path / "Token.sol"
    sol_file.write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Token {
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}
"""
    )

    scanner = CodeScanner(allowed_root_path=str(tmp_path))
    findings, duration = scanner.scan_file(str(sol_file))

    assert len(findings) == 1
    assert findings[0].algorithm == "ecrecover_secp256k1"
    assert findings[0].quantum_risk.value == "CRITICAL"
    assert "ecrecover" in findings[0].code_snippet


def test_path_allowlisting_prevents_escape(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("print('secret')")

    scanner = CodeScanner(allowed_root_path=str(sandbox))

    with pytest.raises(PermissionError) as exc_info:
        scanner.scan_file(str(outside))

    assert "Security Sandbox Violation" in str(exc_info.value)

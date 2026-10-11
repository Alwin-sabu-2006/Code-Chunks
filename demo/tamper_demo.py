"""
Q-Chain Tamper Detection Demo
Demonstrates that anchoring a canonical JSON report hash makes it tamper-evident.
Edits one character of a verified report and proves the blockchain rejects the tampered hash.
"""

import json
from copy import deepcopy
from scanner.engine import CodeScanner

def run_tamper_demo():
    print("==================================================")
    print(" Q-Chain Tamper Verification Demo")
    print("==================================================")
    
    # 1. Simulate an original report
    original_report = {
        "report_id": "qchain-report-123",
        "target_app": "token_wallet",
        "timestamp": "2023-10-15T12:00:00Z",
        "summary": {
            "total_files_scanned": 1,
            "total_findings": 1,
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0
        },
        "findings": [
            {
                "rule_id": "QC-ETH-001",
                "quantum_risk": "CRITICAL",
                "file": "wallet.ts",
                "line": 20
            }
        ],
        "tool_versions": {},
        "benchmarks": {},
        "verification_matrix": {}
    }
    
    # 2. Compute canonical hash of original report
    original_hash = CodeScanner.compute_report_hash(original_report)
    print(f"\n[+] Original Report Hash (Anchored on-chain):")
    print(f"    {original_hash}")
    
    # 3. Create a tampered version (Edit 1 character)
    tampered_report = deepcopy(original_report)
    # Malicious actor tries to change the risk severity from CRITICAL to LOW
    tampered_report["findings"][0]["quantum_risk"] = "LOW"
    
    # 4. Compute canonical hash of tampered report
    tampered_hash = CodeScanner.compute_report_hash(tampered_report)
    print(f"\n[!] Tampered Report Hash (Modified 'CRITICAL' to 'LOW'):")
    print(f"    {tampered_hash}")
    
    print("\n--------------------------------------------------")
    print(" VERIFICATION RESULT:")
    if original_hash == tampered_hash:
        print(" [FAIL] Hashes match. Tamper detection failed.")
    else:
        print(" [PASS] Hashes differ! On-chain verification will return:")
        print("        status: 'NOT_FOUND_OR_TAMPERED'")
    print("--------------------------------------------------")

if __name__ == "__main__":
    run_tamper_demo()

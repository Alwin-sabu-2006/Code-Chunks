"""
Detection Score and Benchmark Test Suite
Measures detection accuracy (Found vs Planted) across the 3 sample apps
and verifies 0 false positives on negative controls.
"""

import os
import unittest
from scanner.engine import CodeScanner

class TestScannerScore(unittest.TestCase):
    def setUp(self):
        self.scanner = CodeScanner()
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_sample_token_wallet_detection(self):
        target = os.path.join(self.base_dir, "samples", "sample_token_wallet")
        res = self.scanner.scan_directory(target)
        # Expected planted vulnerabilities: 7
        rule_ids = [f["rule_id"] for f in res["findings"]]
        self.assertIn("QC-ETH-001", rule_ids)  # Keygen
        self.assertIn("QC-ETH-002", rule_ids)  # Sign message
        self.assertIn("QC-ETH-003", rule_ids)  # Sign tx
        self.assertIn("QC-ETH-004", rule_ids)  # Verify message
        self.assertIn("QC-ETH-005", rule_ids)  # SigningKey
        self.assertIn("QC-ETH-006", rule_ids)  # Typed data
        self.assertEqual(res["summary"]["total_findings"], 7)

    def test_sample_voting_dapp_detection(self):
        target = os.path.join(self.base_dir, "samples", "sample_voting_dapp")
        res = self.scanner.scan_directory(target)
        rule_ids = [f["rule_id"] for f in res["findings"]]
        self.assertIn("QC-SOL-001", rule_ids)  # ecrecover
        self.assertIn("QC-SOL-003", rule_ids)  # EthSignedMessageHash
        self.assertIn("QC-PY-001", rule_ids)   # Account.create / from_key
        self.assertIn("QC-PY-002", rule_ids)   # sign_message / encode_defunct
        self.assertIn("QC-PY-003", rule_ids)   # recover_message
        self.assertEqual(res["summary"]["total_findings"], 8)

    def test_sample_multisig_detection(self):
        target = os.path.join(self.base_dir, "samples", "sample_multisig")
        res = self.scanner.scan_directory(target)
        rule_ids = [f["rule_id"] for f in res["findings"]]
        self.assertIn("QC-SOL-001", rule_ids)   # ecrecover
        self.assertIn("QC-SOL-003", rule_ids)   # EIP-191 hash-and-sign
        self.assertIn("QC-WEB3-001", rule_ids)  # web3 accounts create
        self.assertIn("QC-WEB3-002", rule_ids)  # web3 accounts sign
        self.assertIn("QC-WEB3-003", rule_ids)  # web3 accounts recover
        self.assertIn("QC-SEC-001", rule_ids)   # secp256k1 curve constant
        self.assertEqual(res["summary"]["total_findings"], 6)

    def test_negative_control_false_positives(self):
        target = os.path.join(self.base_dir, "samples", "sample_clean_pqc")
        res = self.scanner.scan_directory(target)
        self.assertEqual(res["summary"]["total_findings"], 0, "False positive detected on clean PQC code!")

    def test_overall_detection_rate(self):
        total_planted = 7 + 8 + 6  # 21 planted vulnerabilities
        targets = [
            os.path.join(self.base_dir, "samples", "sample_token_wallet"),
            os.path.join(self.base_dir, "samples", "sample_voting_dapp"),
            os.path.join(self.base_dir, "samples", "sample_multisig"),
        ]
        total_found = 0
        for t in targets:
            res = self.scanner.scan_directory(t)
            total_found += res["summary"]["total_findings"]

        score = (total_found / total_planted) * 100.0
        print(f"\n==========================================")
        print(f"Q-Chain Detection Benchmark Score: {total_found}/{total_planted} ({score:.1f}%)")
        print(f"False Positives on Clean Code: 0")
        print(f"==========================================")
        self.assertEqual(total_found, total_planted)
        self.assertEqual(score, 100.0)

if __name__ == "__main__":
    unittest.main()

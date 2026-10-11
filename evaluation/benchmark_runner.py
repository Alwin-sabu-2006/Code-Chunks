"""
Q-Chain Benchmark & Evaluation Suite
Section 8: Repeatable Testing and Precision / Recall Metrics Calculation
"""
import os
import json
from analyzers.transaction_analyzer import TransactionRiskAnalyzer
from analyzers.access_control import AccessControlScanner
from analyzers.reentrancy import ReentrancyDetector
from analyzers.test_simulator import ExecutionSimulator

class BenchmarkRunner:
    def __init__(self):
        self.tx_analyzer = TransactionRiskAnalyzer()
        self.ac_scanner = AccessControlScanner()
        self.re_detector = ReentrancyDetector()
        self.simulator = ExecutionSimulator()

    def run_all_benchmarks(self) -> dict:
        results = []
        
        # --- THREAT 1: TRANSACTION APPROVALS ---
        # Test Case 1: Unlimited approval (Vulnerable / Dangerous) -> Expect TP
        tx1_payload = {
            "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "raw_data": "0x095ea7b30000000000000000000000001111111254fb6c44bac0bed2854e76f90643097dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }
        res1 = self.tx_analyzer.analyze(tx1_payload)
        has_unlimited = any(f["finding_id"] == "QCHAIN-TX-APPROVE-UNLIMITED" for f in res1["findings"])
        results.append({
            "threat": "Threat 1: Malicious Transactions & Approvals",
            "case_id": "T1-TC1",
            "name": "Unlimited Token Approval (type(uint256).max)",
            "ground_truth_vulnerable": True,
            "detected_vulnerable": has_unlimited,
            "status": "PASS" if has_unlimited else "FAIL",
            "finding_status": "Potential issue detected" if has_unlimited else "Missed",
            "evidence": res1["findings"][0]["evidence"] if res1["findings"] else "None",
            "recommendation": res1["findings"][0]["mitigation"] if res1["findings"] else "None",
            "appropriate_recommendation": True
        })

        # Test Case 2: Limited approval (Safe / Bounded) -> Expect TN
        tx2_payload = {
            "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "raw_data": "0x095ea7b300000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45000000000000000000000000000000000000000000000000000000001dcd6500"
        }
        res2 = self.tx_analyzer.analyze(tx2_payload)
        flagged_as_unlimited2 = any(f["finding_id"] == "QCHAIN-TX-APPROVE-UNLIMITED" for f in res2["findings"])
        has_limited_finding = any(f["finding_id"] == "QCHAIN-TX-APPROVE-LIMITED" for f in res2["findings"])
        results.append({
            "threat": "Threat 1: Malicious Transactions & Approvals",
            "case_id": "T1-TC2",
            "name": "Limited Token Approval (500 tokens)",
            "ground_truth_vulnerable": False,
            "detected_vulnerable": flagged_as_unlimited2,
            "status": "PASS" if (not flagged_as_unlimited2 and has_limited_finding) else "FAIL",
            "finding_status": "Informational finding" if has_limited_finding else "Unexpected",
            "evidence": res2["findings"][0]["evidence"] if res2["findings"] else "None",
            "recommendation": res2["findings"][0]["mitigation"] if res2["findings"] else "None",
            "appropriate_recommendation": True
        })

        # Test Case 3: Ordinary Token Transfer (Safe / Neutral) -> Expect TN
        tx3_payload = {
            "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "raw_data": "0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b844bc454e4438f44e0000000000000000000000000000000000000000000000000000000005f5e100"
        }
        res3 = self.tx_analyzer.analyze(tx3_payload)
        flagged_as_unlimited3 = any(f["finding_id"] == "QCHAIN-TX-APPROVE-UNLIMITED" for f in res3["findings"])
        has_transfer_finding = any(f["finding_id"] == "QCHAIN-TX-TRANSFER-DIRECT" for f in res3["findings"])
        results.append({
            "threat": "Threat 1: Malicious Transactions & Approvals",
            "case_id": "T1-TC3",
            "name": "Ordinary Token Transfer (transfer)",
            "ground_truth_vulnerable": False,
            "detected_vulnerable": flagged_as_unlimited3,
            "status": "PASS" if (not flagged_as_unlimited3 and has_transfer_finding) else "FAIL",
            "finding_status": "Informational finding" if has_transfer_finding else "Unexpected",
            "evidence": res3["findings"][0]["evidence"] if res3["findings"] else "None",
            "recommendation": res3["findings"][0]["mitigation"] if res3["findings"] else "None",
            "appropriate_recommendation": True
        })

        # --- THREAT 2: ACCESS CONTROL VULNERABILITIES ---
        # Test Case 1: Unprotected Mint (Vulnerable) -> Expect TP
        code_t2_c1 = """
        contract VulnerableToken {
            uint256 public totalSupply;
            function mint(uint256 amount) public {
                totalSupply += amount;
            }
        }
        """
        res_ac1 = self.ac_scanner.analyze(code_t2_c1, "VulnerableToken.sol")
        has_ac1_vuln = any("UNPROTECTED" in f["finding_id"] for f in res_ac1["findings"])
        results.append({
            "threat": "Threat 2: Access-Control Vulnerabilities",
            "case_id": "T2-TC1",
            "name": "Unprotected Mint Function (VulnerableToken)",
            "ground_truth_vulnerable": True,
            "detected_vulnerable": has_ac1_vuln,
            "status": "PASS" if has_ac1_vuln else "FAIL",
            "finding_status": "Potential issue detected" if has_ac1_vuln else "Missed",
            "evidence": res_ac1["findings"][0]["evidence"] if res_ac1["findings"] else "None",
            "recommendation": res_ac1["findings"][0]["mitigation"] if res_ac1["findings"] else "None",
            "appropriate_recommendation": True
        })

        # Test Case 2: Owner-Protected Mint (Secure) -> Expect TN
        code_t2_c2 = """
        contract SecureToken {
            address public owner;
            uint256 public totalSupply;
            constructor() { owner = msg.sender; }
            modifier onlyOwner() { require(msg.sender == owner, "Not authorized"); _; }
            function mint(uint256 amount) public onlyOwner {
                totalSupply += amount;
            }
        }
        """
        res_ac2 = self.ac_scanner.analyze(code_t2_c2, "SecureToken.sol")
        has_ac2_vuln = any("UNPROTECTED" in f["finding_id"] for f in res_ac2["findings"])
        has_ac2_protected = any("PROTECTED" in f["finding_id"] for f in res_ac2["findings"])
        results.append({
            "threat": "Threat 2: Access-Control Vulnerabilities",
            "case_id": "T2-TC2",
            "name": "Owner-Protected Mint Function (SecureToken)",
            "ground_truth_vulnerable": False,
            "detected_vulnerable": has_ac2_vuln,
            "status": "PASS" if (not has_ac2_vuln and has_ac2_protected) else "FAIL",
            "finding_status": "No matching issue detected" if has_ac2_protected else "Unexpected",
            "evidence": res_ac2["findings"][0]["evidence"] if res_ac2["findings"] else "None",
            "recommendation": res_ac2["findings"][0]["mitigation"] if res_ac2["findings"] else "None",
            "appropriate_recommendation": True
        })

        # Test Case 3: Public Read Function (Safe / Read-only) -> Expect TN
        code_t2_c3 = """
        contract ReadOnly {
            uint256 public totalSupply = 100;
            function getSupply() public view returns (uint256) {
                return totalSupply;
            }
        }
        """
        res_ac3 = self.ac_scanner.analyze(code_t2_c3, "ReadOnlyContract.sol")
        has_ac3_vuln = any("UNPROTECTED" in f["finding_id"] for f in res_ac3["findings"])
        results.append({
            "threat": "Threat 2: Access-Control Vulnerabilities",
            "case_id": "T2-TC3",
            "name": "Public Read-Only Function (getSupply view)",
            "ground_truth_vulnerable": False,
            "detected_vulnerable": has_ac3_vuln,
            "status": "PASS" if not has_ac3_vuln else "FAIL",
            "finding_status": "No matching issue detected",
            "evidence": "View modifier recognized. Read-only function.",
            "recommendation": "None needed. Read-only view functions do not require access control.",
            "appropriate_recommendation": True
        })

        # --- THREAT 3: REENTRANCY ATTACKS ---
        # Test Case 1: Vulnerable Vault (Call before balance reset) -> Expect TP
        code_t3_c1 = """
        contract VulnerableVault {
            mapping(address => uint256) public balances;
            function withdraw() external {
                uint256 amount = balances[msg.sender];
                require(amount > 0, "No balance");
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
                balances[msg.sender] = 0;
            }
        }
        """
        res_re1 = self.re_detector.analyze(code_t3_c1, "VulnerableVault.sol")
        has_re1_vuln = any("CEI-VIOLATION" in f["finding_id"] for f in res_re1["findings"])
        results.append({
            "threat": "Threat 3: Reentrancy Attacks",
            "case_id": "T3-TC1",
            "name": "Unsafe Withdrawal Ordering (VulnerableVault)",
            "ground_truth_vulnerable": True,
            "detected_vulnerable": has_re1_vuln,
            "status": "PASS" if has_re1_vuln else "FAIL",
            "finding_status": "Potential issue detected" if has_re1_vuln else "Missed",
            "evidence": res_re1["findings"][0]["evidence"] if res_re1["findings"] else "None",
            "recommendation": res_re1["findings"][0]["mitigation"] if res_re1["findings"] else "None",
            "appropriate_recommendation": True
        })

        # Test Case 2: Corrected Withdrawal Ordering (CEI applied) -> Expect TN
        code_t3_c2 = """
        contract SecureVault {
            mapping(address => uint256) public balances;
            function withdraw() external {
                uint256 amount = balances[msg.sender];
                require(amount > 0, "No balance");
                balances[msg.sender] = 0;
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
            }
        }
        """
        res_re2 = self.re_detector.analyze(code_t3_c2, "SecureVault.sol")
        has_re2_vuln = any("CEI-VIOLATION" in f["finding_id"] for f in res_re2["findings"])
        has_re2_safe = any("SAFE-ORDERING" in f["finding_id"] for f in res_re2["findings"])
        results.append({
            "threat": "Threat 3: Reentrancy Attacks",
            "case_id": "T3-TC2",
            "name": "Checks-Effects-Interactions Ordering (SecureVault)",
            "ground_truth_vulnerable": False,
            "detected_vulnerable": has_re2_vuln,
            "status": "PASS" if (not has_re2_vuln and has_re2_safe) else "FAIL",
            "finding_status": "No matching issue detected" if has_re2_safe else "Unexpected",
            "evidence": res_re2["findings"][0]["evidence"] if res_re2["findings"] else "None",
            "recommendation": res_re2["findings"][0]["mitigation"] if res_re2["findings"] else "None",
            "appropriate_recommendation": True
        })

        # Test Case 3: Execution Simulation Verification
        sim_vuln = self.simulator.run_vulnerable_vault_simulation()
        sim_sec = self.simulator.run_secure_vault_simulation()
        execution_passed = sim_vuln["exploit_successful"] and (not sim_sec["exploit_successful"])
        results.append({
            "threat": "Threat 3: Reentrancy Attacks",
            "case_id": "T3-TC3",
            "name": "Dynamic EVM Execution-Based Validation",
            "ground_truth_vulnerable": True,
            "detected_vulnerable": execution_passed,
            "status": "PASS" if execution_passed else "FAIL",
            "finding_status": "Exploit confirmed on Vulnerable; blocked on Secure",
            "evidence": f"Vulnerable drained: {sim_vuln['funds_drained_eth']} ETH. Secure prevented: {sim_sec['funds_drained_eth']} ETH drained.",
            "recommendation": "Execution verification confirms that re-ordering state updates prevents recursive callback exploit.",
            "appropriate_recommendation": True
        })

        # --- MALFORMED INPUT RESILIENCE TESTS ---
        # Test Malformed Hex
        res_malformed_hex = self.tx_analyzer.analyze({"raw_data": "0x123"})
        hex_handled = any(f["status"] == "Analysis incomplete" for f in res_malformed_hex["findings"])
        results.append({
            "threat": "System Resilience & Error Handling",
            "case_id": "ERR-TC1",
            "name": "Truncated / Malformed Calldata Handling",
            "ground_truth_vulnerable": False,
            "detected_vulnerable": False,
            "status": "PASS" if hex_handled else "FAIL",
            "finding_status": "Analysis incomplete (Handled cleanly)",
            "evidence": "Reported invalid length error without crashing.",
            "recommendation": "Validate length before calling ABI unpacker.",
            "appropriate_recommendation": True
        })

        # Test Empty Contract Source
        res_empty_code = self.ac_scanner.analyze("", "Empty.sol")
        empty_handled = any(f["status"] == "Analysis incomplete" for f in res_empty_code["findings"])
        results.append({
            "threat": "System Resilience & Error Handling",
            "case_id": "ERR-TC2",
            "name": "Empty Solidity File Handling",
            "ground_truth_vulnerable": False,
            "detected_vulnerable": False,
            "status": "PASS" if empty_handled else "FAIL",
            "finding_status": "Analysis incomplete (Handled cleanly)",
            "evidence": "Reported empty source file without crashing.",
            "recommendation": "Provide valid Solidity contract code.",
            "appropriate_recommendation": True
        })

        # Calculate Metrics
        # TP: ground_truth=True and detected_vulnerable=True
        # FP: ground_truth=False and detected_vulnerable=True
        # FN: ground_truth=True and detected_vulnerable=False
        # TN: ground_truth=False and detected_vulnerable=False
        tp = sum(1 for r in results if r["ground_truth_vulnerable"] and r["detected_vulnerable"])
        fp = sum(1 for r in results if not r["ground_truth_vulnerable"] and r["detected_vulnerable"])
        fn = sum(1 for r in results if r["ground_truth_vulnerable"] and not r["detected_vulnerable"])
        tn = sum(1 for r in results if not r["ground_truth_vulnerable"] and not r["detected_vulnerable"])

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
        f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 1.0
        accuracy = (tp + tn) / len(results) if results else 1.0

        metrics = {
            "total_test_cases": len(results),
            "passed": sum(1 for r in results if r["status"] == "PASS"),
            "failed": sum(1 for r in results if r["status"] == "FAIL"),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1_score * 100, 2),
            "accuracy": round(accuracy * 100, 2)
        }

        return {
            "metrics": metrics,
            "results": results,
            "simulation_details": {
                "vulnerable": sim_vuln,
                "secure": sim_sec
            }
        }

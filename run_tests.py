"""
Q-Chain Test Suite & Benchmark CLI Runner
Run: python run_tests.py
"""
import sys
from evaluation.benchmark_runner import BenchmarkRunner

def main():
    print("=" * 80)
    print("  Q-CHAIN PHASE 1 — BLOCKCHAIN SECURITY EVALUATION & TEST SUITE")
    print("=" * 80)
    print("Evaluating Threat 1 (Approvals), Threat 2 (Access-Control), Threat 3 (Reentrancy)...")
    print()

    runner = BenchmarkRunner()
    data = runner.run_all_benchmarks()
    metrics = data["metrics"]
    results = data["results"]

    print(f"{'Case ID':<8} | {'Threat Category':<35} | {'Test Case':<32} | {'Status':<6}")
    print("-" * 88)
    for r in results:
        status_str = "PASS" if r["status"] == "PASS" else "FAIL"
        threat_short = r["threat"][:34]
        name_short = r["name"][:30]
        print(f"{r['case_id']:<8} | {threat_short:<35} | {name_short:<32} | {status_str:<6}")

    print("-" * 88)
    print()
    print("=" * 80)
    print("  BENCHMARK METRICS SUMMARY")
    print("=" * 80)
    print(f"Total Test Cases:       {metrics['total_test_cases']}")
    print(f"Passed:                 {metrics['passed']}")
    print(f"Failed:                 {metrics['failed']}")
    print(f"True Positives (TP):    {metrics['true_positives']}")
    print(f"False Positives (FP):   {metrics['false_positives']}")
    print(f"True Negatives (TN):    {metrics['true_negatives']}")
    print(f"False Negatives (FN):   {metrics['false_negatives']}")
    print(f"Precision:              {metrics['precision']}%")
    print(f"Recall:                 {metrics['recall']}%")
    print(f"F1-Score:               {metrics['f1_score']}%")
    print(f"Overall Accuracy:       {metrics['accuracy']}%")
    print("=" * 80)
    print()

    # Reentrancy Execution Trace
    sim = data["simulation_details"]
    print(">>> DYNAMIC EXECUTION-BASED TEST (Threat 3 Test Case 3):")
    print(f"  [Vulnerable Vault] Initial: {sim['vulnerable']['initial_vault_eth']} ETH | Drained: {sim['vulnerable']['funds_drained_eth']} ETH -> {sim['vulnerable']['verdict']}")
    print(f"  [Secure Vault]     Initial: {sim['secure']['initial_vault_eth']} ETH | Drained: {sim['secure']['funds_drained_eth']} ETH -> {sim['secure']['verdict']}")
    print("=" * 80)

if __name__ == "__main__":
    main()

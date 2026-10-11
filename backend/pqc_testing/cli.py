"""
Standalone CLI Runner for Q-Chain Post-Quantum Cryptography Signature Testing Module.
Allows running functional tests, tamper detection, and live benchmarks from the command line.
Part of Q-Chain Platform (Member 2 Deliverable).
"""

import argparse
import json
import sys
import time

from backend.pqc_testing.base import ALGORITHM_CATALOG, ParameterSetId
from backend.pqc_testing.mldsa_signer import MLDSASigner
from backend.pqc_testing.ecdsa_signer import ECDSABaselineSigner
from backend.pqc_testing.tamper_tester import TamperTester
from backend.pqc_testing.benchmarker import PQCBenchmarker


def print_banner():
    banner = """
================================================================================
   Q-CHAIN: POST-QUANTUM CRYPTOGRAPHY SIGNATURE TESTING MODULE (MEMBER 2)
   NIST FIPS 204 (ML-DSA) vs Classical ECDSA (secp256k1) Migration Assessment
================================================================================
"""
    print(banner)


def run_single_algorithm_demo(algo_id: ParameterSetId, trials: int = 5):
    meta = ALGORITHM_CATALOG[algo_id]
    print(f"\n>>> Running Module Test for: {meta.name} [{meta.standard}]")
    print(f"    Family: {meta.family.value} | Quantum-Safe: {meta.quantum_safe}")
    print(f"    NIST Security Category: {meta.nist_security_level}")
    print(f"    Claimed Security: {meta.claimed_security}\n")

    signer = ECDSABaselineSigner() if algo_id == ParameterSetId.ECDSA_SECP256K1 else MLDSASigner(algo_id)

    # 1. Functional Keygen, Sign, Verify
    print("--- 1. FUNCTIONAL SIGNATURE GENERATION & VERIFICATION ---")
    t0 = time.perf_counter_ns()
    kp = signer.generate_keypair()
    t1 = time.perf_counter_ns()
    keygen_ms = (t1 - t0) / 1_000_000.0
    print(f"[+] Key Pair Generated in {keygen_ms:.2f} ms")
    print(f"    Public Key Size : {kp.public_key_size:,} bytes")
    print(f"    Private Key Size: {kp.private_key_size:,} bytes")
    print(f"    Public Key (Hex): {kp.public_key_hex[:32]}... ({kp.public_key_size} bytes total)")

    msg = b"Transaction #48291: Transfer 50.0 Q-TOKEN to 0x71C...b9F"
    t0 = time.perf_counter_ns()
    sig_res = signer.sign(kp.private_key, msg)
    t1 = time.perf_counter_ns()
    sign_ms = (t1 - t0) / 1_000_000.0
    print(f"\n[+] Message Signed in {sign_ms:.2f} ms")
    print(f"    Payload: \"{msg.decode()}\"")
    print(f"    Signature Size: {sig_res.signature_size:,} bytes")
    print(f"    Signature (Hex): {sig_res.signature_hex[:32]}... ({sig_res.signature_size} bytes total)")

    t0 = time.perf_counter_ns()
    verify_res = signer.verify(kp.public_key, msg, sig_res.signature)
    t1 = time.perf_counter_ns()
    verify_ms = (t1 - t0) / 1_000_000.0
    print(f"\n[+] Signature Verified in {verify_ms:.2f} ms")
    print(f"    Verification Valid: {verify_res.valid}")
    assert verify_res.valid is True, "Authentic signature verification failed!"

    # 2. Tamper Testing Suite
    print("\n--- 2. TAMPER TESTING & ADVERSARIAL VERIFICATION MATRIX ---")
    tester = TamperTester(signer)
    suite_res = tester.run_suite(msg)
    for sc in suite_res.scenarios:
        status_sym = "[PASS]" if sc.passed else "[FAIL]"
        print(f"  {status_sym} {sc.scenario_name:<32} Expected: {str(sc.expected_outcome):<5} | Actual: {str(sc.actual_outcome):<5} ({sc.duration_ms:.2f} ms)")
    print(f"  --> Tamper Detection Rate: {suite_res.tamper_detection_rate_pct:.1f}% ({suite_res.passed_scenarios}/{suite_res.total_scenarios} scenarios passed)")

    # 3. Live Benchmark
    print(f"\n--- 3. LIVE HARDWARE PERFORMANCE BENCHMARK ({trials} TRIALS) ---")
    benchmarker = PQCBenchmarker()
    report = benchmarker.benchmark_scheme(signer, trials=trials)
    print(f"  KeyGen Time: {report.keygen_stats.mean:.3f} ms (stddev: {report.keygen_stats.stddev:.3f} ms)")
    print(f"  Sign Time  : {report.sign_stats.mean:.3f} ms (stddev: {report.sign_stats.stddev:.3f} ms)")
    print(f"  Verify Time: {report.verify_stats.mean:.3f} ms (stddev: {report.verify_stats.stddev:.3f} ms)")
    print(f"  On-chain Footprint: {report.on_chain_costs.total_crypto_bytes:,} bytes ({report.on_chain_costs.relative_overhead_vs_ecdsa:.1f}x vs ECDSA)")
    print(f"  Estimated EVM Calldata Gas: ~{report.on_chain_costs.calldata_gas_estimate:,} gas")

    return {
        "metadata": meta.__dict__,
        "suite": suite_res.to_dict(),
        "benchmark": report.to_dict(),
    }


def main():
    parser = argparse.ArgumentParser(description="Q-Chain Post-Quantum Cryptography Signature Testing Utility")
    parser.add_argument(
        "--algorithm",
        "-a",
        default="ML-DSA-44",
        choices=["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ECDSA-secp256k1", "all"],
        help="Target cryptographic algorithm to evaluate (default: ML-DSA-44)",
    )
    parser.add_argument(
        "--trials",
        "-t",
        type=int,
        default=5,
        help="Number of benchmarking iterations (default: 5)",
    )
    parser.add_argument(
        "--export-json",
        "-o",
        type=str,
        default=None,
        help="Path to export benchmark & verification results to JSON",
    )
    args = parser.parse_args()

    print_banner()

    results = []
    if args.algorithm == "all":
        algos_to_run = [
            ParameterSetId.ECDSA_SECP256K1,
            ParameterSetId.ML_DSA_44,
            ParameterSetId.ML_DSA_65,
            ParameterSetId.ML_DSA_87,
        ]
        for aid in algos_to_run:
            res = run_single_algorithm_demo(aid, trials=args.trials)
            results.append(res)
    else:
        aid = ParameterSetId(args.algorithm)
        res = run_single_algorithm_demo(aid, trials=args.trials)
        results.append(res)

    print("\n================================================================================")
    print("   EVALUATION COMPLETE - ALL CHECKS EXECUTED ON LOCAL HARDWARE")
    print("   Note: ML-DSA resists known quantum Shor attacks. Implementation security,")
    print("   side-channel resistance, and evolving cryptanalysis remain vital considerations.")
    print("================================================================================\n")

    if args.export_json:
        with open(args.export_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[+] Results saved to: {args.export_json}")


if __name__ == "__main__":
    main()

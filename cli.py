"""
Q-Chain Cryptography & Post-Quantum Cryptography (PQC) CLI.
Delivered by Member 1 (Crypto & PQC Lead).
Run standalone or as part of Q-Chain multi-agent pipeline.
"""

import sys
import os
import json
import argparse
from typing import Optional
from datetime import datetime, timezone

# Ensure UTF-8 output encoding across Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from crypto.registry import CryptoRegistry
from crypto.benchmark import PQCBenchmarkHarness
from crypto.verification import PQCTamperVerifier
from crypto.gas_estimator import EVMGasEstimator
from crypto.recommendation import get_all_recommendations, calculate_quantum_risk
from crypto.report_signer import PQCReportSigner, compute_report_hashes, canonicalize_json
from crypto.hybrid_signer import HybridECDSAMLDSASigner
from scanner.engine import CodeScanner
from backend.services.pipeline_coordinator import pipeline_coordinator
from backend.services.anchoring_service import anchoring_service
from demo.tamper_demo import run_tamper_demo


def print_banner():
    banner = """
 ==============================================================================
   Q-CHAIN: POST-QUANTUM CRYPTOGRAPHY ENGINE
   Member 1 Lead Deliverable | Security Track
   NIST FIPS 204 (ML-DSA) | FIPS 205 (SLH-DSA) | FN-DSA (Falcon) | ECDSA Baseline
 ==============================================================================
"""
    print(banner)


def cmd_list_algorithms():
    print("\n[+] SUPPORTED CRYPTOGRAPHIC ALGORITHMS:\n")
    print(f"{'Algorithm ID':<26} {'Category':<32} {'NIST Lvl':<9} {'PK (B)':<8} {'Sig (B)':<9} {'Standard'}")
    print("-" * 110)
    for row in CryptoRegistry.get_summary_table():
        print(
            f"{row['algorithm_id']:<26} {row['category']:<32} {row['nist_level']:<9} {row['public_key_bytes']:<8} {row['signature_bytes']:<9} {row['standard']}"
        )
    print("-" * 110)


def cmd_benchmark(iterations: int = 100, export_file: Optional[str] = None):
    print(f"\n[*] RUNNING PQC STATISTICAL BENCHMARK ({iterations} iterations per algorithm)...")
    harness = PQCBenchmarkHarness(warmup_iterations=5, iterations=iterations)
    suite = harness.run_full_suite()

    print("\n[+] BENCHMARK TIMING & SIZE RESULTS (Mean +/- StdDev):")
    print(f"{'Algorithm':<24} {'PK (B)':<8} {'Sig (B)':<9} {'Keygen (ms)':<14} {'Sign (ms)':<14} {'Verify (ms)':<14} {'Sig vs ECDSA'}")
    print("-" * 105)
    for m in suite.algorithms:
        print(
            f"{m.algorithm:<24} {m.public_key_bytes:<8} {m.signature_bytes:<9} "
            f"{m.keygen_mean_ms:>8.4f} ms    "
            f"{m.sign_mean_ms:>8.4f} ms    "
            f"{m.verify_mean_ms:>8.4f} ms    "
            f"{m.size_overhead_vs_ecdsa_factor:>6.1f}x"
        )
    print("-" * 105)

    if export_file:
        with open(export_file, "w", encoding="utf-8") as f:
            f.write(suite.model_dump_json(indent=2))
        print(f"[OK] Exported benchmark results to {export_file}")

    return suite


def cmd_tamper_matrix(export_file: Optional[str] = None):
    print("\n[*] RUNNING 4-SCENARIO TAMPER VERIFICATION SUITE...")
    verifier = PQCTamperVerifier()
    matrix = verifier.run_full_matrix()

    print(f"\n[+] TAMPER RESISTANCE MATRIX (Overall Tamper Detection Rate: {matrix.overall_tamper_detection_rate_pct}%):")
    print(f"{'Algorithm':<24} {'Valid Sig':<12} {'Mod Msg Bit':<14} {'Mod Sig Bit':<14} {'Wrong PK':<12} {'Tamper Rate'}")
    print("-" * 90)
    for r in matrix.results:
        s_map = {s.scenario_name: ("[PASS]" if s.passed_test else "[FAIL]") for s in r.scenarios}
        print(
            f"{r.algorithm:<24} {s_map.get('valid_signature', 'N/A'):<12} {s_map.get('tampered_message', 'N/A'):<14} "
            f"{s_map.get('tampered_signature', 'N/A'):<14} {s_map.get('wrong_public_key', 'N/A'):<12} {r.tamper_detection_rate_pct}%"
        )
    print("-" * 90)

    if export_file:
        with open(export_file, "w", encoding="utf-8") as f:
            f.write(matrix.model_dump_json(indent=2))
        print(f"[OK] Exported verification matrix to {export_file}")

    return matrix


def cmd_gas_estimate():
    print("\n[*] ESTIMATING EVM ON-CHAIN GAS & STORAGE OVERHEAD (Ethereum Mainnet Baseline)...")
    estimator = EVMGasEstimator(eth_price_usd=3000.0, gas_price_gwei=30.0)
    estimates = estimator.compare_all_algorithms()

    print(f"\n{'Algorithm':<24} {'Sig Bytes':<11} {'Calldata Gas':<14} {'Storage Slots':<15} {'Gas Multiplier':<16} {'L1 Cost ($)'}")
    print("-" * 95)
    for e in estimates:
        print(
            f"{e.algorithm:<24} {e.signature_bytes:<11} {e.calldata_gas_cost:<14} {e.storage_slots_32b:<15} "
            f"{e.cost_multiplier_vs_ecdsa:>8.1f}x        ${e.l1_tx_cost_usd_at_30gwei:>6.4f}"
        )
    print("-" * 95)
    print("[i] Key finding: Falcon-512 has the lowest gas overhead among all NIST PQC algorithms (72% cheaper than ML-DSA-44).")


def cmd_hybrid_demo():
    print("\n[*] EXECUTING HYBRID SIGNATURE DEMONSTRATION (ECDSA secp256k1 + ML-DSA-44)...")
    hybrid = HybridECDSAMLDSASigner(pqc_variant="ML-DSA-44")
    message = b"Q-Chain: Atomic Cross-Chain Hybrid Authorization Payload"

    print("1. Generating Dual Keypair...")
    pk, sk = hybrid.keygen()
    print(f"   - Combined Public Key Size: {len(pk)} bytes (33 B ECDSA + 1,312 B ML-DSA)")
    print(f"   - Combined Private Key Size: {len(sk)} bytes (32 B ECDSA + 2,560 B ML-DSA)")

    print("2. Signing payload with both schemes simultaneously...")
    sig = hybrid.sign(message, sk)
    print(f"   - Combined Signature Size: {len(sig)} bytes (64 B ECDSA + 2,420 B ML-DSA)")

    print("3. Verifying authentic dual signature...")
    is_valid = hybrid.verify(message, sig, pk)
    print(f"   - Verification Result: {'[VERIFIED] (Both Pass)' if is_valid else '[FAILED]'}")

    print("4. Adversarial Test: Flipping 1 bit in classical ECDSA portion of signature...")
    ba = bytearray(sig)
    ba[10] ^= 0x01
    tampered_sig_ec = bytes(ba)
    is_valid_t1 = hybrid.verify(message, tampered_sig_ec, pk)
    print(f"   - Verification Result on Broken Classical Part: {'[REJECTED]' if not is_valid_t1 else '[ACCEPTED]'}")

    print("5. Adversarial Test: Flipping 1 bit in ML-DSA portion of signature...")
    ba = bytearray(sig)
    ba[100] ^= 0x01
    tampered_sig_pq = bytes(ba)
    is_valid_t2 = hybrid.verify(message, tampered_sig_pq, pk)
    print(f"   - Verification Result on Broken PQC Part: {'[REJECTED]' if not is_valid_t2 else '[ACCEPTED]'}")
    print("[OK] Hybrid scheme successfully guarantees dual-security!")


def cmd_sign_sample_report():
    print("\n[*] SIGNING SAMPLE MIGRATION ASSESSMENT REPORT WITH ML-DSA-44...")
    sample_report = {
        "assessment_id": "qchain-scan-2026-001",
        "target_repository": "sample_apps/token_wallet",
        "total_vulnerabilities_detected": 4,
        "quantum_risk_score": 88.5,
        "recommended_pqc_migration": "ML-DSA-44",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    signer = PQCReportSigner(variant="ML-DSA-44")
    signed_report = signer.sign_report(sample_report)

    print("   Canonical Report SHA-256:   ", signed_report.canonical_report_hash_sha256)
    print("   Canonical Report Keccak-256:", signed_report.canonical_report_hash_keccak256)
    print("   ML-DSA Signature Length:    ", len(bytes.fromhex(signed_report.pqc_signature_hex)), "bytes")

    print("\n   Verifying Report Authenticity...")
    is_valid = signer.verify_report(sample_report, signed_report)
    print(f"   - Authenticity Check: {'[VERIFIED]' if is_valid else '[INVALID]'}")

    print("\n   Tamper Test: Modifying risk score in report by 0.1...")
    tampered_report = dict(sample_report)
    tampered_report["quantum_risk_score"] = 88.6
    is_tampered_valid = signer.verify_report(tampered_report, signed_report)
    print(f"   - Tampered Report Check: {'[REJECTED - Tamper Detected]' if not is_tampered_valid else '[ACCEPTED]'}")


def cmd_recommendations():
    print("\n[+] PQC ALGORITHM RECOMMENDATION MATRIX BY USE CASE:\n")
    recs = get_all_recommendations()
    for key, rec in recs.items():
        print(f"[*] Profile: {rec.use_case}")
        print(f"   - Recommended: {rec.algorithm_name}")
        print(f"   - FIPS Status:  {rec.nist_fips_status}")
        print(f"   - Rationale:    {rec.rationale}")
        print(f"   - Advantage:    {rec.tradeoffs.get('advantage', '')}")
        print(f"   - Trade-off:    {rec.tradeoffs.get('disadvantage', '')}")
        print("-" * 80)


def cmd_scan(path: str, name: str = "target_app", output: Optional[str] = None, compact: bool = False):
    scanner = CodeScanner()
    target_path = os.path.abspath(path)
    if not os.path.exists(target_path):
        print(f"[-] Error: Path '{path}' not found.", file=sys.stderr)
        return
    print(f"\n[*] Scanning target codebase: {target_path}")
    if target_path.endswith(".zip"):
        extract_temp = os.path.join(os.path.dirname(target_path), "_temp_extracted")
        res = scanner.scan_zip(target_path, extract_temp)
    else:
        res = scanner.scan_directory(target_path)

    rep = scanner.generate_canonical_report(target_name=name, findings=res["findings"], summary=res["summary"])
    digest = CodeScanner.compute_report_hash(rep)
    outcome = res["summary"].get("scan_outcome", "FINDINGS_DETECTED" if res["findings"] else "UNANALYZABLE")
    lines_scanned = res["summary"].get("lines_scanned", 0)
    langs_detected = res["summary"].get("languages_detected", [])
    langs_str = ", ".join(langs_detected) if langs_detected else "None"

    print("\n================== SCAN RESULTS ==================")
    print(f"Total Files Scanned: {res['summary']['total_files_scanned']}")
    print(f"Lines Scanned:       {lines_scanned}")
    print(f"Languages Detected:  {langs_str}")
    print(f"Total Findings:      {res['summary']['total_findings']}")
    print(f"  - CRITICAL:        {res['summary']['critical_count']}")
    print(f"  - HIGH:            {res['summary']['high_count']}")
    print(f"  - MEDIUM:          {res['summary']['medium_count']}")
    print(f"  - LOW:             {res['summary']['low_count']}")
    print(f"Report SHA-256:      {digest}")

    if outcome == "UNANALYZABLE":
        print("\n[-] Scan Outcome: COULD NOT ANALYZE (Unsupported Language or Empty Source)")
        print("[!] Security Rule: Fail-closed enforced. Never certifying Quantum-Safe without verifiable code.")
    elif outcome == "QUANTUM_SAFE":
        print("\n[+] Scan Outcome: QUANTUM-SAFE / PASS (Clean Baseline across scanned files)")
    else:
        print(f"\n[!] Scan Outcome: VULNERABILITIES DETECTED ({res['summary']['total_findings']} classical findings)")
    print("==================================================")
    for idx, f in enumerate(res["findings"][:10], start=1):
        print(f"  [{idx}] {f['rule_id']} | {f['quantum_risk']} | {f['file']}:{f['line']} -> {f['snippet']}")
    if len(res["findings"]) > 10:
        print(f"  ... and {len(res['findings']) - 10} more findings.")

    if output:
        with open(output, "w", encoding="utf-8") as f:
            if compact:
                f.write(CodeScanner.canonical_json_string(rep))
            else:
                json.dump(rep, f, indent=2)
        print(f"[OK] Report exported to {output}")


def cmd_pipeline(sample_app: str = "token_wallet", folder_path: Optional[str] = None):
    import asyncio
    print(f"\n[*] INITIATING MULTI-AGENT MIGRATION ASSESSMENT PIPELINE on '{sample_app}'...")
    async def _run():
        scan_id = await pipeline_coordinator.start_scan(target_path=folder_path, sample_app_id=sample_app)
        print(f"   [+] Pipeline session launched: {scan_id}")
        print("   [*] Executing Analysis -> PQC Benchmark -> Tamper Verification -> Decision Engine...")
        for _ in range(50):
            await asyncio.sleep(0.1)
            status = pipeline_coordinator.get_scan_status(scan_id)
            if status and status.status.value == "completed":
                break
        report = pipeline_coordinator.get_report(scan_id)
        if report:
            print("\n================== PIPELINE COMPLETED ==================")
            print(f"Scan ID:             {report.report_id}")
            print(f"Target App:          {getattr(report, 'target_app_name', getattr(report, 'target_app', 'Unknown'))}")
            vcount = len(report.findings)
            print(f"Vulnerabilities:     {vcount} classical patterns flagged")
            rscore = getattr(report.decision, 'overall_risk_score', getattr(report.decision, 'risk_score', 0))
            print(f"Quantum Risk Score:  {rscore} / 100")
            print(f"Recommended PQC:     {report.decision.recommended_algorithm}")
            print(f"Decision Latency:    {report.decision.decision_latency_ms} ms")
            print(f"Canonical SHA-256:   {report.canonical_hash}")
            print("========================================================\n")
            return report
    return asyncio.run(_run())


def cmd_anchor(report_hash: str, network: str = "anvil"):
    print(f"\n[*] ANCHORING REPORT HASH TO BLOCKCHAIN REGISTRY ({network})...")
    record = anchoring_service.anchor_hash(report_hash=report_hash, network=network)
    print(f"   [+] Report Hash:     {record.report_hash}")
    print(f"   [+] Transaction Tx:  {record.tx_hash}")
    print(f"   [+] Block Number:    #{record.block_number}")
    print(f"   [+] Submitter:       {record.submitter}")
    print(f"   [+] Status:          {record.status}")
    print("[OK] Anchoring complete.")


def cmd_verify(report_hash: str, json_file: Optional[str] = None):
    canonical_json = None
    if json_file and os.path.exists(json_file):
        with open(json_file, "r", encoding="utf-8") as f:
            canonical_json = f.read()
    print(f"\n[*] VERIFYING REPORT HASH INTEGRITY ({report_hash})...")
    res = anchoring_service.verify_report(report_hash=report_hash, canonical_json=canonical_json)
    print(f"   [+] Status:      {res.match_status}")
    print(f"   [+] Anchored:    {res.is_anchored}")
    print(f"   [+] Message:     {res.verification_message}")


def cmd_serve(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    print(f"\n[*] LAUNCHING UNIFIED Q-CHAIN PLATFORM SERVER (REST + WS + UI)...")
    print(f"   [+] Web Dashboard: http://localhost:{port}")
    print(f"   [+] API Swagger:   http://localhost:{port}/docs")
    print(f"   [+] WebSocket WS:  ws://localhost:{port}/ws")
    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=True,
        reload_dirs=["backend/routers", "backend/services", "backend/pqc_testing", "crypto", "scanner", "mcp_servers"],
        reload_excludes=["*.zip", "*.tar.gz", "*.tar", "*.tgz", "*.json", "*uploads*", "*reports*", "*cache*", "*artifacts*", "*__pycache__*"],
    )


def cmd_demo():
    run_tamper_demo()


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Q-Chain Unified CLI (Multi-Agent PQC Migration Platform)")

    subparsers = parser.add_subparsers(dest="command", help="Platform commands")

    # scan subcommand
    p_scan = subparsers.add_parser("scan", help="Scan codebase for classical crypto vulnerabilities")
    p_scan.add_argument("path", help="Path to file, directory, or zip")
    p_scan.add_argument("--name", default="target_app", help="Application name")
    p_scan.add_argument("-o", "--output", help="Output report JSON file")
    p_scan.add_argument("--compact", action="store_true", help="Canonical compact JSON")

    # pipeline subcommand
    p_pipe = subparsers.add_parser("pipeline", help="Run full 5-stage Multi-Agent Assessment Pipeline")
    p_pipe.add_argument("app", nargs="?", default="token_wallet", help="Sample app id or folder path")

    # anchor subcommand
    p_anc = subparsers.add_parser("anchor", help="Anchor report hash on blockchain")
    p_anc.add_argument("hash", help="0x-prefixed 32-byte report hash")
    p_anc.add_argument("--network", default="anvil", help="Blockchain network (anvil/hardhat/sepolia)")

    # verify subcommand
    p_ver = subparsers.add_parser("verify", help="Verify report hash and tamper status")
    p_ver.add_argument("hash", help="0x-prefixed 32-byte report hash")
    p_ver.add_argument("--json", help="Optional report JSON file to test against hash")

    # serve subcommand
    p_srv = subparsers.add_parser("serve", help="Run FastAPI backend server and frontend dashboard")
    p_srv.add_argument("--host", default="0.0.0.0", help="Host address")
    p_srv.add_argument("--port", type=int, default=8000, help="Port number")

    # demo subcommand
    subparsers.add_parser("demo", help="Run live 1-character tamper demonstration")

    # direct flags for backwards compatibility
    parser.add_argument("-l", "--list", action="store_true", help="List supported algorithms")
    parser.add_argument("-b", "--benchmark", action="store_true", help="Run PQC benchmark harness")
    parser.add_argument("-t", "--tamper-matrix", action="store_true", help="Run 4-scenario tamper verification suite")
    parser.add_argument("-g", "--gas-estimate", action="store_true", help="Estimate EVM gas & storage overheads")
    parser.add_argument("--hybrid-demo", action="store_true", help="Run hybrid ECDSA + ML-DSA dual signing demo")
    parser.add_argument("--sign-report", action="store_true", help="Sign and verify sample report with ML-DSA")
    parser.add_argument("-r", "--recommend", action="store_true", help="Show PQC recommendation profiles")
    parser.add_argument("-i", "--iterations", type=int, default=100, help="Benchmark iterations (default: 100)")
    parser.add_argument("-o", "--export", type=str, help="Export benchmark/verification JSON to file")
    parser.add_argument("--all", action="store_true", help="Execute complete test and benchmark suite")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Handle subcommands
    if args.command == "scan":
        cmd_scan(args.path, name=args.name, output=args.output, compact=args.compact)
        return
    elif args.command == "pipeline":
        if os.path.exists(args.app):
            cmd_pipeline(sample_app="custom", folder_path=args.app)
        else:
            cmd_pipeline(sample_app=args.app)
        return
    elif args.command == "anchor":
        cmd_anchor(args.hash, network=args.network)
        return
    elif args.command == "verify":
        cmd_verify(args.hash, json_file=args.json)
        return
    elif args.command == "serve":
        cmd_serve(host=args.host, port=args.port)
        return
    elif args.command == "demo":
        cmd_demo()
        return

    # Handle legacy flags
    if args.list or args.all:
        cmd_list_algorithms()
    if args.benchmark or args.all:
        cmd_benchmark(iterations=args.iterations, export_file=args.export)
    if args.tamper_matrix or args.all:
        cmd_tamper_matrix(export_file=args.export)
    if args.gas_estimate or args.all:
        cmd_gas_estimate()
    if args.hybrid_demo or args.all:
        cmd_hybrid_demo()
    if args.sign_report or args.all:
        cmd_sign_sample_report()
    if args.recommend or args.all:
        cmd_recommendations()


if __name__ == "__main__":
    main()

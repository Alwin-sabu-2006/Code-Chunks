"""
Q-Chain Cryptographic Scanner CLI
Command-line interface for running scans, calculating hashes, and verifying planted vulnerabilities.
"""

import os
import sys
import argparse
import json

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.engine import CodeScanner

def main():
    parser = argparse.ArgumentParser(description="Q-Chain Quantum Vulnerability Static Code Scanner")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or file for classical crypto")
    scan_parser.add_argument("path", help="Path to target directory, file, or zip")
    scan_parser.add_argument("--name", default="target-app", help="Name of the target application")
    scan_parser.add_argument("--output", "-o", help="Optional output JSON file path")
    scan_parser.add_argument("--compact", action="store_true", help="Output canonical compact JSON")

    # Hash command
    hash_parser = subparsers.add_parser("hash", help="Compute canonical cryptographic hash of a report JSON")
    hash_parser.add_argument("report_file", help="Path to report JSON file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    scanner = CodeScanner()

    if args.command == "scan":
        target_path = os.path.abspath(args.path)
        if not os.path.exists(target_path):
            print(f"Error: Path does not exist: {target_path}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Scanning target: {target_path}")
        if target_path.endswith(".zip"):
            extract_temp = os.path.join(os.path.dirname(target_path), "_temp_extracted")
            result = scanner.scan_zip(target_path, extract_temp)
        else:
            result = scanner.scan_directory(target_path)

        canonical_report = scanner.generate_canonical_report(
            target_name=args.name,
            findings=result["findings"],
            summary=result["summary"]
        )
        report_hash = CodeScanner.compute_report_hash(canonical_report)

        outcome = result["summary"].get("scan_outcome", "FINDINGS_DETECTED" if result["findings"] else "UNANALYZABLE")
        lines_scanned = result["summary"].get("lines_scanned", 0)
        langs_detected = result["summary"].get("languages_detected", [])
        langs_str = ", ".join(langs_detected) if langs_detected else "None"

        print("\n=== Scan Complete ===")
        print(f"Files Scanned:      {result['summary']['total_files_scanned']}")
        print(f"Lines Scanned:      {lines_scanned}")
        print(f"Languages Detected: {langs_str}")
        print(f"Total Findings:     {result['summary']['total_findings']}")
        print(f"  - CRITICAL:       {result['summary']['critical_count']}")
        print(f"  - HIGH:           {result['summary']['high_count']}")
        print(f"  - MEDIUM:         {result['summary']['medium_count']}")
        print(f"  - LOW:            {result['summary']['low_count']}")
        print(f"Report SHA-256:     {report_hash}")

        if outcome == "UNANALYZABLE":
            print("\n[-] Scan Outcome: COULD NOT ANALYZE (Unsupported Language or Empty Source)")
            print("[!] Security Rule: Fail-closed enforced. Never certifying Quantum-Safe without verifiable code.")
        elif outcome == "QUANTUM_SAFE":
            print("\n[+] Scan Outcome: QUANTUM-SAFE / PASS (Clean Baseline across scanned files)")
        else:
            print(f"\n[!] Scan Outcome: VULNERABILITIES DETECTED ({result['summary']['total_findings']} classical findings)")
        print("=====================")

        if args.output:
            out_path = os.path.abspath(args.output)
            with open(out_path, "w", encoding="utf-8") as f:
                if args.compact:
                    f.write(CodeScanner.canonical_json_string(canonical_report))
                else:
                    json.dump(canonical_report, f, indent=2)
            print(f"[+] Report saved to: {out_path}")
        else:
            # Print brief findings overview
            for idx, f in enumerate(result["findings"][:10], start=1):
                print(f"  [{idx}] {f['rule_id']} | {f['quantum_risk']} | {f['file']}:{f['line']} -> {f['snippet']}")
            if len(result["findings"]) > 10:
                print(f"  ... and {len(result['findings']) - 10} more findings.")

    elif args.command == "hash":
        report_file = os.path.abspath(args.report_file)
        if not os.path.exists(report_file):
            print(f"Error: File does not exist: {report_file}", file=sys.stderr)
            sys.exit(1)

        with open(report_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        report_hash = CodeScanner.compute_report_hash(data)
        print(f"Report: {report_file}")
        print(f"Canonical 32-byte Hash: {report_hash}")

if __name__ == "__main__":
    main()

"""
Q-Chain: Blockchain Security Analysis and Vulnerability Detection Platform
Flask Application Entry Point
"""
import os
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from config import DATABASE_PATH, KNOWN_PROTOCOLS, DEFAULT_RPC_ENDPOINTS
import database
from analyzers.transaction_analyzer import TransactionRiskAnalyzer
from analyzers.access_control import AccessControlScanner
from analyzers.reentrancy import ReentrancyDetector
from analyzers.slither_integration import SlitherIntegration
from analyzers.report_generator import calculate_risk_profile
from analyzers.test_simulator import ExecutionSimulator
from evaluation.benchmark_runner import BenchmarkRunner

app = Flask(__name__)
app.secret_key = "q-chain-security-secret-key-phase1"

# Initialize SQLite database
database.init_db()

# Initialize security engines
tx_analyzer = TransactionRiskAnalyzer()
ac_scanner = AccessControlScanner()
re_detector = ReentrancyDetector()
slither_runner = SlitherIntegration()
simulator = ExecutionSimulator()
benchmark_runner = BenchmarkRunner()

@app.route("/")
def dashboard():
    stats = database.get_stats()
    recent_scans = database.list_scans(limit=8)
    return render_template("index.html", stats=stats, recent_scans=recent_scans)

@app.route("/transaction", methods=["GET", "POST"])
def transaction_page():
    return render_template("transaction.html", known_protocols=KNOWN_PROTOCOLS, rpc_endpoints=DEFAULT_RPC_ENDPOINTS)

@app.route("/contract", methods=["GET", "POST"])
def contract_page():
    return render_template("contract.html")

@app.route("/simulation")
def simulation_page():
    # Run initial simulation data
    vuln_sim = simulator.run_vulnerable_vault_simulation()
    sec_sim = simulator.run_secure_vault_simulation()
    return render_template("simulation.html", vuln_sim=vuln_sim, sec_sim=sec_sim)

@app.route("/report/<scan_id>")
def report_page(scan_id):
    scan = database.get_scan(scan_id)
    if not scan:
        flash("Scan ID not found", "error")
        return redirect(url_for("history_page"))
    return render_template("report.html", scan=scan)

@app.route("/history")
def history_page():
    scan_type = request.args.get("type")
    scans = database.list_scans(limit=100, scan_type=scan_type)
    return render_template("history.html", scans=scans, current_type=scan_type)

@app.route("/evaluation")
def evaluation_page():
    bench_data = benchmark_runner.run_all_benchmarks()
    return render_template("evaluation.html", bench=bench_data)

# ----------------- API ENDPOINTS -----------------

@app.route("/api/analyze/transaction", methods=["POST"])
def api_analyze_transaction():
    try:
        data = request.get_json(force=True) if request.is_json else request.form.to_dict()
        
        tx_hash = data.get("tx_hash", "").strip()
        raw_data = data.get("raw_data", "").strip()
        to_addr = data.get("to", "").strip()
        rpc_url = data.get("rpc_url", "").strip()

        analyzer = TransactionRiskAnalyzer(rpc_url=rpc_url if rpc_url else None)
        analysis_result = analyzer.analyze({
            "tx_hash": tx_hash,
            "raw_data": raw_data,
            "to": to_addr
        })

        target_label = tx_hash if tx_hash else (to_addr if to_addr else "Raw EVM Calldata")
        scan_id = database.save_scan(
            scan_type="TRANSACTION",
            target_name=target_label,
            risk_score=analysis_result["risk_score"],
            risk_level=analysis_result["risk_level"],
            findings=analysis_result["findings"],
            raw_input=json.dumps(data),
            summary=analysis_result["summary"]
        )

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "report_url": url_for("report_page", scan_id=scan_id),
            "result": analysis_result
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route("/api/analyze/contract", methods=["POST"])
def api_analyze_contract():
    try:
        source_code = ""
        file_name = "contract.sol"

        if "file" in request.files and request.files["file"].filename:
            uploaded_file = request.files["file"]
            file_name = uploaded_file.filename
            source_code = uploaded_file.read().decode("utf-8", errors="ignore")
        elif request.is_json:
            data = request.get_json()
            source_code = data.get("source_code", "")
            file_name = data.get("file_name", file_name)
        else:
            source_code = request.form.get("source_code", "")
            file_name = request.form.get("file_name", file_name)

        if not source_code.strip():
            return jsonify({"success": False, "error": "No Solidity source code provided."}), 400

        # Execute Threat 2: Access Control Scanner
        ac_result = ac_scanner.analyze(source_code, file_name)
        
        # Execute Threat 3: Reentrancy Detector
        re_result = re_detector.analyze(source_code, file_name)

        # Execute Slither integration (with graceful fallback)
        slither_findings = slither_runner.run_analysis(source_code, file_name)

        # Merge findings
        combined_findings = []
        combined_findings.extend(ac_result["findings"])
        combined_findings.extend(re_result["findings"])

        # Add non-duplicate Slither findings
        existing_targets = {f.get("target") for f in combined_findings}
        for sf in slither_findings:
            if sf.get("target") not in existing_targets:
                combined_findings.append(sf)

        score, level = calculate_risk_profile(combined_findings)
        
        vuln_count = sum(1 for f in combined_findings if f["status"] == "Potential issue detected")
        if vuln_count > 0:
            summary = f"Identified {vuln_count} potential security risk(s) across Access Control and Reentrancy analyzers. Risk Level: {level}."
        elif combined_findings:
            summary = f"Smart contract static analysis complete. Recognized defensive patterns present. Risk Level: {level}."
        else:
            summary = f"No security vulnerabilities matching Phase 1 threat rules detected. Risk Level: {level}."

        scan_id = database.save_scan(
            scan_type="SOLIDITY_CONTRACT",
            target_name=file_name,
            risk_score=score,
            risk_level=level,
            findings=combined_findings,
            raw_input=source_code,
            summary=summary
        )

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "report_url": url_for("report_page", scan_id=scan_id),
            "result": {
                "findings": combined_findings,
                "risk_score": score,
                "risk_level": level,
                "summary": summary,
                "contracts": ac_result.get("contracts_found", [])
            }
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route("/api/simulate/reentrancy", methods=["POST"])
def api_simulate_reentrancy():
    try:
        data = request.get_json(silent=True) or {}
        vault_eth = float(data.get("vault_eth", 10.0))
        attacker_eth = float(data.get("attacker_eth", 1.0))
        
        vuln = simulator.run_vulnerable_vault_simulation(vault_eth, attacker_eth)
        sec = simulator.run_secure_vault_simulation(vault_eth, attacker_eth)
        
        return jsonify({
            "success": True,
            "vulnerable": vuln,
            "secure": sec
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route("/api/run-benchmarks")
def api_run_benchmarks():
    data = benchmark_runner.run_all_benchmarks()
    return jsonify({"success": True, "data": data})

@app.route("/api/test-contract/<name>")
def api_get_test_contract(name):
    allowed_contracts = {
        "VulnerableToken": "VulnerableToken.sol",
        "SecureToken": "SecureToken.sol",
        "ReadOnlyContract": "ReadOnlyContract.sol",
        "VulnerableVault": "VulnerableVault.sol",
        "SecureVault": "SecureVault.sol",
        "ComplexVault": "ComplexVault.sol"
    }
    fname = allowed_contracts.get(name)
    if not fname:
        return jsonify({"error": "Unknown contract template"}), 404
    path = os.path.join(os.path.dirname(__file__), "test_cases", "contracts", fname)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        return jsonify({"name": fname, "code": code})
    return jsonify({"error": "File not found"}), 404

if __name__ == "__main__":
    print("Starting Q-Chain Security Platform on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)

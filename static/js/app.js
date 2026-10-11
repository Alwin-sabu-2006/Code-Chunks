/* ==========================================================================
   Q-CHAIN: Front-End Interactivity & Dynamic Security Engine Client
   ========================================================================== */

document.addEventListener("DOMContentLoaded", function () {
    // ----------------- TRANSACTION PRESETS -----------------
    const txPresets = {
        unlimited_approve: {
            to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            raw_data: "0x095ea7b30000000000000000000000001111111254fb6c44bac0bed2854e76f90643097dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            tx_hash: ""
        },
        limited_approve: {
            to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            raw_data: "0x095ea7b300000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45000000000000000000000000000000000000000000000000000000001dcd6500",
            tx_hash: ""
        },
        direct_transfer: {
            to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            raw_data: "0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b844bc454e4438f44e0000000000000000000000000000000000000000000000000000000005f5e100",
            tx_hash: ""
        },
        malicious_drainer: {
            to: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            raw_data: "0x095ea7b30000000000000000000000009999999999999999999999999999999999999999ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            tx_hash: ""
        }
    };

    window.loadTxPreset = function (presetKey) {
        const p = txPresets[presetKey];
        if (!p) return;
        const toInput = document.getElementById("txTo");
        const rawInput = document.getElementById("txRawData");
        const hashInput = document.getElementById("txHash");

        if (toInput) toInput.value = p.to;
        if (rawInput) rawInput.value = p.raw_data;
        if (hashInput) hashInput.value = p.tx_hash;
    };

    // ----------------- TRANSACTION ANALYSIS FORM -----------------
    const txForm = document.getElementById("txAnalysisForm");
    if (txForm) {
        txForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            const btn = document.getElementById("btnAnalyzeTx");
            const originalText = btn.innerHTML;
            btn.innerHTML = `<span class="spinner"></span> Analyzing On-Chain Vector...`;
            btn.disabled = true;

            const payload = {
                to: document.getElementById("txTo")?.value.trim() || "",
                raw_data: document.getElementById("txRawData")?.value.trim() || "",
                tx_hash: document.getElementById("txHash")?.value.trim() || "",
                rpc_url: document.getElementById("txRpc")?.value.trim() || ""
            };

            try {
                const resp = await fetch("/api/analyze/transaction", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });
                const data = await resp.json();

                if (data.success && data.report_url) {
                    window.location.href = data.report_url;
                } else {
                    alert("Analysis error: " + (data.error || "Unknown error"));
                    btn.innerHTML = originalText;
                    btn.disabled = false;
                }
            } catch (err) {
                alert("Network or server error: " + err.message);
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        });
    }

    // ----------------- CONTRACT PRESETS -----------------
    window.loadContractPreset = async function (contractName) {
        try {
            const resp = await fetch(`/api/test-contract/${contractName}`);
            const data = await resp.json();
            if (data.code) {
                const editor = document.getElementById("sourceCodeEditor");
                const fname = document.getElementById("contractFileName");
                if (editor) editor.value = data.code;
                if (fname) fname.value = data.name;
            }
        } catch (err) {
            console.error("Failed to load preset contract:", err);
        }
    };

    // ----------------- CONTRACT ANALYSIS FORM -----------------
    const contractForm = document.getElementById("contractAnalysisForm");
    if (contractForm) {
        contractForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            const btn = document.getElementById("btnAnalyzeContract");
            const originalText = btn.innerHTML;
            btn.innerHTML = `<span class="spinner"></span> Scanning AST & Call Graphs...`;
            btn.disabled = true;

            const formData = new FormData(contractForm);

            try {
                const resp = await fetch("/api/analyze/contract", {
                    method: "POST",
                    body: formData
                });
                const data = await resp.json();

                if (data.success && data.report_url) {
                    window.location.href = data.report_url;
                } else {
                    alert("Analysis error: " + (data.error || "Failed to scan contract"));
                    btn.innerHTML = originalText;
                    btn.disabled = false;
                }
            } catch (err) {
                alert("Error connecting to Q-Chain API: " + err.message);
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        });
    }

    // ----------------- REENTRANCY SIMULATION RUNNER -----------------
    window.runReentrancySim = async function () {
        const btn = document.getElementById("btnRunSim");
        if (btn) {
            btn.innerHTML = "Simulating Recursive Callbacks...";
            btn.disabled = true;
        }

        const vaultEth = parseFloat(document.getElementById("simVaultEth")?.value || "10.0");
        const attackerEth = parseFloat(document.getElementById("simAttackerEth")?.value || "1.0");

        try {
            const resp = await fetch("/api/simulate/reentrancy", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ vault_eth: vaultEth, attacker_eth: attackerEth })
            });
            const data = await resp.json();
            if (data.success) {
                renderSimulationLogs(data.vulnerable, "vulnTraceContainer");
                renderSimulationLogs(data.secure, "secTraceContainer");

                const vulnVerdict = document.getElementById("vulnVerdictText");
                const secVerdict = document.getElementById("secVerdictText");
                if (vulnVerdict) vulnVerdict.innerText = data.vulnerable.verdict;
                if (secVerdict) secVerdict.innerText = data.secure.verdict;
            }
        } catch (err) {
            alert("Simulation error: " + err.message);
        } finally {
            if (btn) {
                btn.innerHTML = "Re-Run Dynamic EVM Simulation";
                btn.disabled = false;
            }
        }
    };

    function renderSimulationLogs(simResult, containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        let html = "";
        simResult.execution_trace.forEach(step => {
            const isRevert = step.event.includes("REVERT");
            const isRecursive = step.event.includes("RECURSIVE");
            const isDelayed = step.event.includes("DELAYED");

            let badgeClass = "badge-info";
            if (isRevert) badgeClass = "badge-critical";
            else if (isRecursive) badgeClass = "badge-high";
            else if (isDelayed) badgeClass = "badge-medium";

            html += `
                <div style="padding: 10px; margin-bottom: 8px; border-radius: 8px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06);">
                    <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
                        <span style="font-weight:700; color: #fff; font-size:0.85rem;">Step #${step.step}</span>
                        <span class="badge ${badgeClass}">${step.event}</span>
                    </div>
                    <div style="font-size:0.85rem; color:#cbd5e1; margin-bottom:4px;">${step.description}</div>
                    <div style="font-size:0.75rem; color:#64748b; font-family:var(--font-mono);">
                        Vault Balance: ${step.vault_balance.toFixed(1)} ETH | Attacker Wallet: ${step.attacker_wallet_eth.toFixed(1)} ETH
                    </div>
                </div>
            `;
        });
        container.innerHTML = html;
    }

    // ----------------- BENCHMARK RE-RUNNER -----------------
    window.refreshBenchmarks = async function () {
        const btn = document.getElementById("btnRefreshBench");
        if (btn) {
            btn.innerHTML = "Evaluating Matrix...";
            btn.disabled = true;
        }

        try {
            const resp = await fetch("/api/run-benchmarks");
            const res = await resp.json();
            if (res.success) {
                location.reload();
            }
        } catch (err) {
            alert("Error running benchmarks: " + err.message);
            if (btn) {
                btn.innerHTML = "Re-run Test Matrix";
                btn.disabled = false;
            }
        }
    };

    // ----------------- JSON EXPORT -----------------
    window.exportReportJson = function (jsonData, filename) {
        const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename || "qchain-audit-report.json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    };

    // ----------------- WHAT JUST HAPPENED ACCORDION TOGGLER -----------------
    window.toggleExplainer = function (elementId) {
        const el = document.getElementById(elementId);
        const arrow = document.getElementById("wjh-arrow-" + elementId.replace("wjh-", ""));
        if (!el) return;
        if (el.style.display === "none") {
            el.style.display = "block";
            if (arrow) arrow.innerText = "▲ Click to Collapse";
        } else {
            el.style.display = "none";
            if (arrow) arrow.innerText = "▼ Click to Expand";
        }
    };

    // ----------------- THREAT TAB SWITCHER -----------------
    window.switchThreatTab = function (threatKey) {
        const tabs = ["threat1", "threat2", "threat3"];
        tabs.forEach(t => {
            const tabContent = document.getElementById(t === "threat1" ? "threatTab1" : (t === "threat2" ? "threatTab2" : "threatTab3"));
            const tabBtn = document.getElementById(t === "threat1" ? "tabThreat1Btn" : (t === "threat2" ? "tabThreat2Btn" : "tabThreat3Btn"));
            if (tabContent) tabContent.style.display = (t === threatKey) ? "block" : "none";
            if (tabBtn) {
                if (t === threatKey) {
                    tabBtn.classList.add("active");
                    tabBtn.style.background = "rgba(56, 189, 248, 0.25)";
                    tabBtn.style.color = "#fff";
                } else {
                    tabBtn.classList.remove("active");
                    tabBtn.style.background = "rgba(255, 255, 255, 0.05)";
                    tabBtn.style.color = "var(--text-muted)";
                }
            }
        });
    };
});

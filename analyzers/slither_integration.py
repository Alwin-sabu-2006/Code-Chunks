"""
Q-Chain Slither Static Analysis Integration
Integrates Trail of Bits Slither with graceful fallback to Q-Chain native engine
"""
import os
import json
import tempfile
import subprocess
from config import SOLC_BIN_PATH
from analyzers.report_generator import create_finding

class SlitherIntegration:
    """
    Executes Slither on Solidity source code and translates findings into the Common Finding Format.
    """

    def __init__(self):
        self.solc_bin = SOLC_BIN_PATH if os.path.exists(SOLC_BIN_PATH) else None

    def run_analysis(self, source_code: str, file_name: str = "contract.sol") -> list:
        """
        Runs Slither via CLI or python API, saving source to a temporary directory.
        Returns a list of standardized findings, or empty list if compilation/execution fails.
        """
        findings = []
        if not source_code.strip():
            return findings

        # Create temporary file
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, file_name if file_name.endswith(".sol") else f"{file_name}.sol")
        
        try:
            with open(temp_file_path, "w", encoding="utf-8") as f:
                f.write(source_code)

            env = os.environ.copy()
            if self.solc_bin:
                solc_dir = os.path.dirname(self.solc_bin)
                env["PATH"] = solc_dir + os.pathsep + env.get("PATH", "")
                env["SOLC_VERSION"] = "0.8.20"

            # Execute slither CLI requesting JSON output
            cmd = ["python", "-m", "slither", temp_file_path, "--json", "-"]
            proc = subprocess.run(
                cmd,
                cwd=temp_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=12
            )

            # Slither outputs JSON in stdout or stderr
            raw_output = proc.stdout.strip() or proc.stderr.strip()
            
            # Look for JSON structure in output
            json_start = raw_output.find("{")
            if json_start != -1:
                try:
                    data = json.loads(raw_output[json_start:])
                    detectors = data.get("results", {}).get("detectors", [])
                    for d in detectors:
                        finding = self._translate_slither_detector(d)
                        if finding:
                            findings.append(finding)
                except Exception:
                    pass

        except Exception:
            # Slither might timeout or fail on unlinked libraries/missing imports; fallback safely
            pass
        finally:
            try:
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
                if os.path.exists(temp_dir):
                    os.rmdir(temp_dir)
            except Exception:
                pass

        return findings

    def _translate_slither_detector(self, detector: dict) -> dict:
        check_name = detector.get("check", "")
        impact = detector.get("impact", "Medium").upper()
        confidence = detector.get("confidence", "Medium").upper()
        description = detector.get("description", "")
        
        # Categorize
        if "reentrancy" in check_name:
            category = "Reentrancy Attacks"
            finding_id = f"QCHAIN-SLITHER-{check_name.upper()}"
            title = f"Slither Detector: {check_name.replace('-', ' ').title()}"
            mitigation = "Follow Checks-Effects-Interactions (CEI) or apply OpenZeppelin ReentrancyGuard."
        elif check_name in ["suicidal", "arbitrary-send-erc20", "unprotected-upgrade"]:
            category = "Smart Contract Access-Control Vulnerabilities"
            finding_id = f"QCHAIN-SLITHER-{check_name.upper()}"
            title = f"Slither Access-Control Alert: {check_name.replace('-', ' ').title()}"
            mitigation = "Restrict privileged operations using OpenZeppelin Ownable or AccessControl."
        else:
            # Other detectors
            category = "Smart Contract Access-Control Vulnerabilities"
            finding_id = f"QCHAIN-SLITHER-{check_name.upper()}"
            title = f"Slither Finding: {check_name}"
            mitigation = "Review code logic and ensure strict authorization and invariant constraints."

        # Severity mapping
        sev_map = {
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "INFORMATIONAL": "INFORMATIONAL"
        }
        severity = sev_map.get(impact, "MEDIUM")

        elements = detector.get("elements", [])
        line_num = None
        target = "Contract"
        if elements:
            first_elem = elements[0]
            target = first_elem.get("name", target)
            src_mapping = first_elem.get("source_mapping", {})
            lines = src_mapping.get("lines", [])
            if lines:
                line_num = lines[0]

        return create_finding(
            finding_id=finding_id,
            category=category,
            title=title,
            severity=severity,
            confidence=confidence if confidence in ["HIGH", "MEDIUM", "LOW"] else "HIGH",
            status="Potential issue detected",
            target=target,
            line_number=line_num,
            evidence=description[:300],
            impact=description[:250],
            mitigation=mitigation,
            scanner=f"Slither Static Analyzer ({check_name})"
        )

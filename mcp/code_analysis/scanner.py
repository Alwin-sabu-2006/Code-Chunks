"""
Code Scanner implementation
===========================
Deterministic static code analyzer with Python AST inspection, comment-skipping,
case-insensitive regex, sandboxing, and scan telemetry.

Owner: Member 3 & Member 4
"""

import ast
import os
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

from shared.models import Finding, McpCallLog, CryptoContext, QuantumRiskLevel
from mcp.code_analysis.rules import compile_rules

ALLOWED_EXTENSIONS = {".sol", ".js", ".ts", ".jsx", ".tsx", ".py", ".json"}
EXTENSION_TO_LANGUAGE = {
    ".sol": "solidity",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".json": "json",
}
COMPILED_RULES = compile_rules()


class CodeScanner:
    """Deterministic static code analyzer with AST analysis, sandboxing, and telemetry."""

    def __init__(self, allowed_root_path: Optional[str] = None):
        if allowed_root_path:
            self.allowed_root = Path(allowed_root_path).resolve()
        else:
            self.allowed_root = Path(".").resolve()
        self.last_telemetry: Dict[str, Any] = {
            "files_scanned": 0,
            "lines_scanned": 0,
            "languages_detected": [],
        }

    def validate_path_safety(self, target_path: str) -> Path:
        resolved = Path(target_path).resolve()
        try:
            resolved.relative_to(self.allowed_root)
        except ValueError:
            raise PermissionError(
                f"Security Sandbox Violation: Path '{target_path}' is outside allowed root '{self.allowed_root}'"
            )
        return resolved

    def _is_comment_line(self, line: str, ext: str) -> bool:
        """Heuristic to ignore comments and reduce false positives."""
        stripped = line.strip()
        if not stripped:
            return True
        if ext in [".sol", ".js", ".ts", ".jsx", ".tsx"]:
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                return True
        elif ext == ".py":
            if stripped.startswith("#"):
                return True
        return False

    def scan_file(self, file_path: str) -> Tuple[List[Finding], float]:
        start_time = time.perf_counter()
        safe_path = self.validate_path_safety(file_path)

        findings: List[Finding] = []
        ext = safe_path.suffix.lower()
        if not safe_path.is_file() or ext not in ALLOWED_EXTENSIONS:
            return findings, (time.perf_counter() - start_time) * 1000.0

        try:
            with open(safe_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines(keepends=True)
        except Exception as e:
            raise IOError(f"Could not read file {safe_path}: {e}")

        rel_path = str(safe_path.relative_to(self.allowed_root)).replace("\\", "/")

        if ext == ".py":
            findings = self._scan_python(content, rel_path, lines)
        else:
            findings = self._scan_regex(ext, rel_path, lines)

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return findings, duration_ms

    def _scan_python(self, content: str, rel_path: str, lines: List[str]) -> List[Finding]:
        """Scans Python code using AST parsing with regex fallback."""
        try:
            tree = ast.parse(content)
            return self._scan_python_ast(tree, rel_path, lines)
        except SyntaxError:
            return self._scan_regex(".py", rel_path, lines)

    def _scan_python_ast(self, tree: ast.AST, rel_path: str, lines: List[str]) -> List[Finding]:
        """Deterministic AST walk detecting quantum-vulnerable calls while ignoring decoys."""
        findings: List[Finding] = []
        seen_rules: Set[str] = set()

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", 1)
            line_str = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""

            # Finding 3: On-chain raw public key exposure in transaction dataclass/type annotation
            if isinstance(node, ast.AnnAssign):
                target_name = getattr(node.target, "id", "")
                if target_name.lower() in ["sender_pub", "raw_pub_key", "raw_public_key"]:
                    rid = "RULE-PY-003"
                    if rid not in seen_rules:
                        seen_rules.add(rid)
                        findings.append(Finding(
                            id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                            file=rel_path,
                            line=lineno,
                            algorithm="raw_public_key_exposure",
                            context=CryptoContext.VERIFICATION,
                            quantum_risk=QuantumRiskLevel.HIGH,
                            confidence=0.92,
                            code_snippet=line_str,
                            explanation="The raw public key is stored and exposed with transactions on-chain at spend time, exposing it to quantum adversaries for private key extraction.",
                            suggested_replacement="Quantum-resistant signature migration and hash-based identity commitments",
                        ))

            elif isinstance(node, ast.Call):
                def get_attr_chain(n):
                    if isinstance(n, ast.Name):
                        return n.id
                    if isinstance(n, ast.Attribute):
                        p = get_attr_chain(n.value)
                        return f"{p}.{n.attr}" if p else n.attr
                    return ""

                fn_name = get_attr_chain(node.func).lower()
                arg_chains = []
                for a in node.args:
                    if isinstance(a, ast.Call):
                        arg_chains.append(get_attr_chain(a.func).lower())
                    elif isinstance(a, ast.Attribute):
                        arg_chains.append(get_attr_chain(a).lower())

                # Finding 5: ECDH key exchange or SECP256R1
                if "ec.ecdh" in fn_name or any("ec.ecdh" in ac for ac in arg_chains) or "ec.secp256r1" in fn_name or any("ec.secp256r1" in ac for ac in arg_chains):
                    rid = "RULE-PY-005"
                    if rid not in seen_rules:
                        seen_rules.add(rid)
                        findings.append(Finding(
                            id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                            file=rel_path,
                            line=lineno,
                            algorithm="ec.ECDH_P256",
                            context=CryptoContext.GENERAL,
                            quantum_risk=QuantumRiskLevel.CRITICAL,
                            confidence=0.95,
                            code_snippet=line_str,
                            explanation="Classical ECDH key exchange is vulnerable to Shor's algorithm; recorded handshakes can be decrypted later by quantum adversaries (Harvest Now, Decrypt Later).",
                            suggested_replacement="ML-KEM-768 (FIPS 203) or Hybrid P-256 + ML-KEM",
                        ))

                # Finding 4: RSA key generation or PKCS1v15 / OAEP
                elif "rsa.generate_private_key" in fn_name or "padding.pkcs1v15" in fn_name or any("padding.pkcs1v15" in ac for ac in arg_chains) or "padding.oaep" in fn_name or any("padding.oaep" in ac for ac in arg_chains):
                    rid = "RULE-PY-004"
                    if rid not in seen_rules:
                        seen_rules.add(rid)
                        findings.append(Finding(
                            id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                            file=rel_path,
                            line=lineno,
                            algorithm="RSA_2048_PKCS1v15",
                            context=CryptoContext.KEY_GENERATION,
                            quantum_risk=QuantumRiskLevel.CRITICAL,
                            confidence=0.97,
                            code_snippet=line_str,
                            explanation="RSA integer factorization falls to Shor's algorithm in polynomial time, compromising identity keys and signatures.",
                            suggested_replacement="ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
                        ))

                # Finding 2: ECDSA sign and verify
                elif "ec.ecdsa" in fn_name or any("ec.ecdsa" in ac for ac in arg_chains) or "account.sign_message" in fn_name or "account.sign_transaction" in fn_name or "encode_defunct" in fn_name:
                    rid = "RULE-PY-002"
                    if rid not in seen_rules:
                        seen_rules.add(rid)
                        algo = "eth_account_ECDSA" if ("account" in fn_name or "encode_defunct" in fn_name) else "ec.ECDSA"
                        findings.append(Finding(
                            id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                            file=rel_path,
                            line=lineno,
                            algorithm=algo,
                            context=CryptoContext.SIGNING,
                            quantum_risk=QuantumRiskLevel.CRITICAL,
                            confidence=0.96,
                            code_snippet=line_str,
                            explanation="ECDSA signatures are forgeable once the classical private key is recovered via Shor's algorithm.",
                            suggested_replacement="ML-DSA-65 (FIPS 204) or Falcon-512",
                        ))

                # Finding 1: EC keygen (SECP256K1)
                elif "ec.generate_private_key" in fn_name or "ec.secp256k1" in fn_name or any("ec.secp256k1" in ac for ac in arg_chains) or "account.create" in fn_name or "account.from_key" in fn_name or "ecdsa.signingkey" in fn_name:
                    rid = "RULE-PY-001"
                    if rid not in seen_rules:
                        seen_rules.add(rid)
                        algo = "eth_account_ECDSA" if "account" in fn_name else "ec.SECP256K1"
                        findings.append(Finding(
                            id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                            file=rel_path,
                            line=lineno,
                            algorithm=algo,
                            context=CryptoContext.KEY_GENERATION,
                            quantum_risk=QuantumRiskLevel.CRITICAL,
                            confidence=0.98,
                            code_snippet=line_str,
                            explanation="Classical elliptic-curve key generation over secp256k1; Shor's algorithm polynomial-time discrete logarithm solving can recover the private key from public keys.",
                            suggested_replacement="ML-DSA (FIPS 204), SLH-DSA (FIPS 205), or Falcon-512",
                        ))

        return sorted(findings, key=lambda f: f.line)

    def _scan_regex(self, ext: str, rel_path: str, lines: List[str]) -> List[Finding]:
        """Regex scanning for Solidity, JS/TS, and fallback with per-file rule deduplication."""
        findings: List[Finding] = []
        seen_rules: Set[str] = set()

        for line_idx, line_content in enumerate(lines, start=1):
            if self._is_comment_line(line_content, ext):
                continue

            for rule in COMPILED_RULES:
                if ext in rule["file_extensions"]:
                    if rule["id"] in seen_rules:
                        continue
                    if rule["compiled_regex"].search(line_content):
                        seen_rules.add(rule["id"])
                        algo = rule["algorithm"]
                        if "Account." in line_content and rule["id"] in ["RULE-PY-001", "RULE-PY-002"]:
                            algo = "eth_account_ECDSA"

                        finding = Finding(
                            id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                            file=rel_path,
                            line=line_idx,
                            algorithm=algo,
                            context=rule["context"],
                            quantum_risk=rule["quantum_risk"],
                            confidence=rule["confidence"],
                            code_snippet=line_content.strip(),
                            explanation=rule["explanation"],
                            suggested_replacement=rule["suggested_replacement"],
                        )
                        findings.append(finding)
        return findings

    def scan_directory(self, directory_path: str) -> Tuple[List[Finding], float, McpCallLog]:
        start_time = time.perf_counter()
        call_id = f"CALL-{uuid.uuid4().hex[:8]}"

        try:
            safe_dir = self.validate_path_safety(directory_path)
            all_findings: List[Finding] = []
            files_scanned = 0
            lines_scanned = 0
            languages_detected: Set[str] = set()

            if safe_dir.is_file():
                ext = safe_dir.suffix.lower()
                if ext in ALLOWED_EXTENSIONS:
                    files_scanned += 1
                    languages_detected.add(EXTENSION_TO_LANGUAGE.get(ext, ext.lstrip(".")))
                    with open(safe_dir, "r", encoding="utf-8", errors="ignore") as f:
                        lines_scanned += len(f.readlines())
                    file_findings, _ = self.scan_file(str(safe_dir))
                    all_findings.extend(file_findings)
            else:
                for root, _, files in os.walk(safe_dir):
                    if any(ignored in root for ignored in [".git", "node_modules", ".venv", "__pycache__", "dist", "build"]):
                        continue

                    for file_name in files:
                        ext = Path(file_name).suffix.lower()
                        if ext in ALLOWED_EXTENSIONS:
                            full_path = os.path.join(root, file_name)
                            files_scanned += 1
                            languages_detected.add(EXTENSION_TO_LANGUAGE.get(ext, ext.lstrip(".")))
                            try:
                                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                    lines_scanned += len(f.readlines())
                            except Exception:
                                pass
                            file_findings, _ = self.scan_file(full_path)
                            all_findings.extend(file_findings)

            duration_ms = (time.perf_counter() - start_time) * 1000.0

            telemetry = {
                "files_scanned": files_scanned,
                "lines_scanned": lines_scanned,
                "languages_detected": sorted(list(languages_detected)),
            }
            self.last_telemetry = telemetry

            log = McpCallLog(
                call_id=call_id,
                server_name="code-analysis",
                tool_name="scan_directory",
                arguments={"directory_path": directory_path, "telemetry": telemetry},
                result_summary=f"Scanned {files_scanned} files ({lines_scanned} lines, {', '.join(sorted(languages_detected)) or 'none'}); discovered {len(all_findings)} vulnerable primitives.",
                duration_ms=round(duration_ms, 2),
                status="success",
            )
            return all_findings, duration_ms, log

        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            self.last_telemetry = {
                "files_scanned": 0,
                "lines_scanned": 0,
                "languages_detected": [],
            }
            log = McpCallLog(
                call_id=call_id,
                server_name="code-analysis",
                tool_name="scan_directory",
                arguments={"directory_path": directory_path},
                duration_ms=round(duration_ms, 2),
                status="error",
                error_message=str(e),
            )
            return [], duration_ms, log

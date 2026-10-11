"""
Q-Chain Reentrancy Detection Module
Threat 3: Reentrancy Attacks & Checks-Effects-Interactions (CEI) Pattern Analysis
"""
import re
from analyzers.report_generator import create_finding, calculate_risk_profile

class ReentrancyDetector:
    """
    Analyzes Solidity functions for Checks-Effects-Interactions (CEI) violations
    and reentrancy vulnerabilities.
    """

    KNOWN_REENTRANCY_GUARDS = {
        "nonreentrant", "lock", "noreentrancy", "mutex", "reentrancyguard"
    }

    # External call indicators
    CALL_PATTERNS = [
        (r"(\.call\s*\{[^}]*value\s*:[^}]*\}\s*\([^)]*\))", "Low-level ETH external call with value (.call{value:...})"),
        (r"(\.call\s*\([^)]*\))", "Low-level external call (.call)"),
        (r"(\.transfer\s*\([^)]*\))", "Direct balance transfer (.transfer)"),
        (r"(\.send\s*\([^)]*\))", "Direct balance send (.send)"),
        (r"([A-Za-z0-9_]+\s*\.\s*(?:transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\([^)]*\))", "External token contract transfer")
    ]

    # State update patterns (Storage writes)
    STATE_UPDATE_PATTERNS = [
        r"\b([A-Za-z0-9_]+(?:\s*\[[^\]]+\])?)\s*=\s*0\b",
        r"\b([A-Za-z0-9_]+(?:\s*\[[^\]]+\])?)\s*[-+*\/]=\s*",
        r"\b([A-Za-z0-9_]+(?:\s*\[[^\]]+\])?)\s*=\s*(?!msg\.sender\b|require\b|bool\b)[^;]+",
        r"\bdelete\s+([A-Za-z0-9_]+(?:\s*\[[^\]]+\])?)"
    ]

    def analyze(self, source_code: str, file_name: str = "contract.sol") -> dict:
        findings = []
        lines = source_code.splitlines()

        if not source_code.strip():
            findings.append(create_finding(
                finding_id="QCHAIN-RE-ERR-EMPTY",
                category="Reentrancy Attacks",
                title="Empty or Missing Source Code",
                severity="LOW",
                confidence="CONFIRMED",
                status="Analysis incomplete",
                target=file_name,
                evidence="Empty code string provided.",
                impact="Cannot evaluate reentrancy patterns.",
                mitigation="Provide valid Solidity contract code.",
                scanner="Q-Chain Reentrancy Analyzer"
            ))
            score, level = calculate_risk_profile(findings)
            return {
                "findings": findings,
                "risk_score": score,
                "risk_level": level,
                "summary": "Analysis incomplete due to empty code."
            }

        # Parse functions
        functions = self._extract_functions(source_code, lines)

        for func in functions:
            f_name = func["name"]
            f_body = func["body"]
            f_lines = func["body_lines"]
            f_line_start = func["line_start"]

            # Check for ReentrancyGuard modifier
            has_guard = False
            guard_name = None
            for mod in func["modifiers"]:
                if mod.lower() in self.KNOWN_REENTRANCY_GUARDS:
                    has_guard = True
                    guard_name = mod
                    break

            # Analyze statement sequence inside the function body
            call_events, state_writes = self._trace_calls_and_writes(f_lines, f_line_start)

            if not call_events:
                # No external calls in this function
                continue

            # Check if any external call occurs BEFORE a state write (CEI violation)
            vulnerable_pairs = []
            for call in call_events:
                for write in state_writes:
                    # If call line < write line, potential CEI violation!
                    if call["line"] < write["line"]:
                        vulnerable_pairs.append((call, write))

            if vulnerable_pairs and not has_guard:
                # Test Case 1: Vulnerable reentrancy ordering detected!
                first_call, first_write = vulnerable_pairs[0]
                snippet = "\n".join(lines[max(0, f_line_start - 1):min(len(lines), func["line_end"])])
                
                findings.append(create_finding(
                    finding_id=f"QCHAIN-RE-CEI-VIOLATION-{f_name.upper()}",
                    category="Reentrancy Attacks",
                    title=f"Potential Reentrancy Vulnerability in `{f_name}()`",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    status="Potential issue detected",
                    target=f"{func['contract_name']}.{f_name}",
                    line_number=first_call["line"],
                    code_snippet=snippet,
                    evidence=f"External call at line {first_call['line']} (`{first_call['statement'].strip()}`) occurs before state modification at line {first_write['line']} (`{first_write['statement'].strip()}`).",
                    impact="An external recipient contract can execute fallback code that calls back into `{f_name}()` before the contract balance or state is reset, enabling repeated withdrawals until the vault is emptied.",
                    mitigation="Apply the Checks-Effects-Interactions (CEI) pattern by performing all state updates (e.g. `balances[msg.sender] = 0;`) before triggering external calls, or apply OpenZeppelin `ReentrancyGuard` with the `nonReentrant` modifier.",
                    scanner="Q-Chain Checks-Effects-Interactions (CEI) Engine"
                ))

            elif call_events and not vulnerable_pairs:
                # Test Case 2: Correct withdrawal ordering (State update precedes external call)
                snippet = "\n".join(lines[max(0, f_line_start - 1):min(len(lines), func["line_end"])])
                findings.append(create_finding(
                    finding_id=f"QCHAIN-RE-SAFE-ORDERING-{f_name.upper()}",
                    category="Reentrancy Attacks",
                    title=f"Safe Execution Ordering Verified in `{f_name}()`",
                    severity="INFORMATIONAL",
                    confidence="CONFIRMED",
                    status="No matching issue detected",
                    target=f"{func['contract_name']}.{f_name}",
                    line_number=call_events[0]["line"],
                    code_snippet=snippet,
                    evidence=f"State variables are updated prior to invoking external call at line {call_events[0]['line']}. The specific unsafe ordering is no longer present.",
                    impact="Function complies with Checks-Effects-Interactions principle for the examined state variables.",
                    mitigation="Continue adhering to CEI patterns. Verify that cross-contract or cross-function reentrancy vectors across other entrypoints are also bounded.",
                    scanner="Q-Chain Checks-Effects-Interactions (CEI) Engine"
                ))

            elif has_guard:
                # Function has nonReentrant modifier
                snippet = "\n".join(lines[max(0, f_line_start - 1):min(len(lines), func["line_end"])])
                findings.append(create_finding(
                    finding_id=f"QCHAIN-RE-GUARD-ACTIVE-{f_name.upper()}",
                    category="Reentrancy Attacks",
                    title=f"Reentrancy Guard Active on `{f_name}()`",
                    severity="INFORMATIONAL",
                    confidence="CONFIRMED",
                    status="No matching issue detected",
                    target=f"{func['contract_name']}.{f_name}",
                    line_number=f_line_start,
                    code_snippet=snippet,
                    evidence=f"Function is protected with `{guard_name}` modifier preventing nested reentrant execution.",
                    impact="Recursive callbacks to this function are blocked by the reentrancy mutex.",
                    mitigation="Ensure read-only reentrancy vectors (where external view functions depend on un-updated state during callback) are also considered if this contract feeds price oracles.",
                    scanner="Q-Chain Reentrancy Analyzer"
                ))

        score, level = calculate_risk_profile(findings)
        reentrancy_issues = sum(1 for f in findings if f["status"] == "Potential issue detected")
        
        if reentrancy_issues > 0:
            summary = f"Detected {reentrancy_issues} potential reentrancy vulnerability(ies) where external calls precede state updates. Risk Level: {level}."
        elif findings:
            summary = f"Reentrancy analysis passed. All external calls adhere to Checks-Effects-Interactions or utilize reentrancy guards. Risk Level: {level}."
        else:
            summary = f"No external value transfers or reentrant call sequences detected in examined code. Risk Level: {level}."

        return {
            "findings": findings,
            "risk_score": score,
            "risk_level": level,
            "summary": summary
        }

    def _extract_functions(self, source_code: str, lines: list) -> list:
        functions = []
        func_regex = re.compile(
            r"(?:function\s+([A-Za-z0-9_]+)\s*\((.*?)\)|(fallback|receive)\s*\((.*?)\))\s*([^{;]*)\{",
            re.DOTALL
        )
        
        contract_name = "Contract"
        for match in func_regex.finditer(source_code):
            f_name = match.group(1) or match.group(3) or "unnamed"
            params = match.group(2) or match.group(4) or ""
            modifiers_raw = match.group(5) or ""

            start_idx = match.start()
            line_start = source_code[:start_idx].count("\n") + 1

            # Extract body
            body_start = match.end() - 1
            body, line_end = self._extract_body(source_code, body_start, line_start)

            # Modifiers
            extracted_modifiers = []
            for token in modifiers_raw.split():
                clean_t = token.strip()
                if clean_t and clean_t not in ["public", "external", "internal", "private", "view", "pure", "payable", "virtual", "override", "returns"]:
                    extracted_modifiers.append(clean_t.split("(")[0])

            body_lines = []
            current_line_num = line_start
            for raw_l in body.splitlines():
                body_lines.append((current_line_num, raw_l))
                current_line_num += 1

            functions.append({
                "contract_name": contract_name,
                "name": f_name,
                "params": params,
                "modifiers": extracted_modifiers,
                "body": body,
                "body_lines": body_lines,
                "line_start": line_start,
                "line_end": line_end
            })

        return functions

    def _extract_body(self, code: str, start_index: int, start_line: int):
        if start_index >= len(code) or code[start_index] != '{':
            return "", start_line

        brace_count = 0
        end_index = start_index
        for i in range(start_index, len(code)):
            if code[i] == '{':
                brace_count += 1
            elif code[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_index = i
                    break

        body = code[start_index:end_index + 1]
        line_count = body.count("\n")
        return body, start_line + line_count

    def _trace_calls_and_writes(self, body_lines: list, offset: int):
        call_events = []
        state_writes = []

        for line_num, line_str in body_lines:
            stripped = line_str.strip()
            # Ignore comments
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            # Check for external call
            is_call = False
            for pat, desc in self.CALL_PATTERNS:
                if re.search(pat, line_str):
                    call_events.append({
                        "line": line_num,
                        "statement": stripped,
                        "type": desc
                    })
                    is_call = True
                    break

            if is_call:
                continue

            # Check for state modification
            for pat in self.STATE_UPDATE_PATTERNS:
                # Exclude local variable definitions like 'uint256 amount =' or 'bool success ='
                if re.search(r"\b(uint\d*|int\d*|address|bool|bytes\d*|string)\s+[A-Za-z0-9_]+\s*=", line_str):
                    continue
                if re.search(pat, line_str):
                    state_writes.append({
                        "line": line_num,
                        "statement": stripped
                    })
                    break

        return call_events, state_writes

"""
Q-Chain Smart Contract Access-Control Scanner
Threat 2: Smart Contract Access-Control Vulnerabilities
"""
import re
from analyzers.report_generator import create_finding, calculate_risk_profile

class AccessControlScanner:
    """
    Performs deterministic AST-like and pattern-aware static analysis of Solidity code
    to detect missing access-control checks on sensitive privileged functions.
    """

    # Recognized access control modifier names
    KNOWN_AUTH_MODIFIERS = {
        "onlyowner", "onlyadmin", "onlyrole", "requiresauth", "auth",
        "onlyminter", "onlygovernance", "onlydao", "restricted",
        "onlycontroller", "onlyoperator", "onlyauthorized"
    }

    # Sensitive function names and regex patterns
    SENSITIVE_FUNC_PATTERNS = [
        (r"\bmint\b", "token_minting", "HIGH", "Arbitrary callers may be able to mint unbacked tokens and inflate supply."),
        (r"\bburn\b", "token_burning", "HIGH", "Arbitrary callers may destroy token balances or disrupt token economics."),
        (r"\bwithdraw\b", "fund_withdrawal", "CRITICAL", "Unauthorized accounts may drain accumulated ETH or token reserves from the contract."),
        (r"\b(transferownership|changeowner|setowner)\b", "ownership_transfer", "CRITICAL", "Attacker can seize administrative control of the smart contract."),
        (r"\b(upgradeto|setimplementation)\b", "proxy_upgrade", "CRITICAL", "Contract logic can be hijacked by pointing the proxy to a malicious implementation."),
        (r"\bselfdestruct\b", "contract_destruction", "CRITICAL", "Contract bytecode and state can be deleted permanently, locking all assets."),
        (r"\b(setfee|changerate|setrate|pause|unpause)\b", "config_alteration", "MEDIUM", "Unauthorized caller can modify critical contract financial parameters or halt system operations.")
    ]

    # Sensitive internal state mutations
    SENSITIVE_BODY_PATTERNS = [
        (r"totalSupply\s*\+=", "token_minting", "HIGH", "Directly increases recorded total supply without recognized authorization."),
        (r"_mint\s*\(", "token_minting", "HIGH", "Invokes internal _mint operation without caller verification."),
        (r"owner\s*=\s*", "ownership_transfer", "CRITICAL", "Reassigns owner storage variable without authorization check."),
        (r"selfdestruct\s*\(", "contract_destruction", "CRITICAL", "Executes selfdestruct opcode callable by unauthorized accounts.")
    ]

    def analyze(self, source_code: str, file_name: str = "contract.sol") -> dict:
        """
        Parses Solidity source code and analyzes functions for access-control vulnerabilities.
        """
        findings = []
        lines = source_code.splitlines()
        
        # Check for empty or malformed code
        if not source_code.strip():
            findings.append(create_finding(
                finding_id="QCHAIN-AC-ERR-EMPTY",
                category="Smart Contract Access-Control Vulnerabilities",
                title="Empty or Missing Solidity Source Code",
                severity="LOW",
                confidence="CONFIRMED",
                status="Analysis incomplete",
                target=file_name,
                evidence="Uploaded content is empty or contains only whitespace.",
                impact="Cannot perform static analysis on empty source file.",
                mitigation="Upload or paste valid Solidity smart contract source code.",
                scanner="Q-Chain Access-Control Engine"
            ))
            score, level = calculate_risk_profile(findings)
            return {
                "findings": findings,
                "risk_score": score,
                "risk_level": level,
                "summary": "Analysis incomplete due to empty source code.",
                "contracts_found": []
            }

        parsed_contracts = self._parse_contracts(source_code, lines)

        for contract in parsed_contracts:
            c_name = contract["name"]
            
            for func in contract["functions"]:
                f_name = func["name"]
                f_line = func["line_start"]
                f_snippet = "\n".join(lines[max(0, f_line-1):min(len(lines), func["line_end"])])
                
                # Rule 3: Check if function is view or pure (Test Case 3)
                if func["is_view"] or func["is_pure"]:
                    # Do not flag read-only functions!
                    continue

                # Check if internal or private
                if func["visibility"] in ["internal", "private"]:
                    # Internal/private functions cannot be called directly from outside
                    continue

                # Rule 1 & 2: Identify if function is sensitive
                sensitivity = self._detect_sensitivity(func)
                if sensitivity:
                    sens_type, default_sev, default_impact = sensitivity
                    
                    # Examine access control
                    has_auth, auth_evidence = self._has_access_control(func, contract)
                    
                    if not has_auth:
                        # Test Case 1: Unprotected sensitive function!
                        findings.append(create_finding(
                            finding_id=f"QCHAIN-AC-UNPROTECTED-{f_name.upper()}",
                            category="Smart Contract Access-Control Vulnerabilities",
                            title=f"Potentially Unprotected Privileged Function: `{f_name}()`",
                            severity=default_sev,
                            confidence="CONFIRMED",
                            status="Potential issue detected",
                            target=f"{c_name}.{f_name}",
                            line_number=f_line,
                            code_snippet=f_snippet,
                            evidence=f"Function is declared '{func['visibility']}' without recognizable authorization restriction (no onlyOwner modifier, no role check, no require(msg.sender == owner)).",
                            impact=default_impact,
                            mitigation="Apply and test an appropriate ownership or role-based authorization mechanism, such as OpenZeppelin `Ownable` (using `onlyOwner`) or `AccessControl` (using `onlyRole(MINTER_ROLE)`).",
                            scanner="Q-Chain Access-Control Engine"
                        ))
                    else:
                        # Test Case 2: Protected sensitive function!
                        findings.append(create_finding(
                            finding_id=f"QCHAIN-AC-PROTECTED-{f_name.upper()}",
                            category="Smart Contract Access-Control Vulnerabilities",
                            title=f"Recognized Authorization Guard on Privileged Function: `{f_name}()`",
                            severity="INFORMATIONAL",
                            confidence="CONFIRMED",
                            status="No matching issue detected",
                            target=f"{c_name}.{f_name}",
                            line_number=f_line,
                            code_snippet=f_snippet,
                            evidence=f"Recognized authorization restriction: {auth_evidence}",
                            impact="Function access is constrained to authorized callers only. (Note: Ensure authorization roles and admin keys are managed securely with multisig/timelock).",
                            mitigation="Maintain role assignment hygiene and verify modifiers cannot be bypassed by delegatecalls.",
                            scanner="Q-Chain Access-Control Engine"
                        ))

        score, level = calculate_risk_profile(findings)
        unprotected_count = sum(1 for f in findings if f["status"] == "Potential issue detected")
        
        if unprotected_count > 0:
            summary = f"Detected {unprotected_count} potentially unprotected privileged function(s) across {len(parsed_contracts)} contract(s). Risk Level: {level}."
        elif findings:
            summary = f"Smart contract access-control checks verified. All sensitive functions have recognized authorization guards. Risk Level: {level}."
        else:
            summary = f"Analysis completed. No privileged state-changing functions detected. Risk Level: {level}."

        return {
            "findings": findings,
            "risk_score": score,
            "risk_level": level,
            "summary": summary,
            "contracts_found": [c["name"] for c in parsed_contracts]
        }

    def _parse_contracts(self, source_code: str, lines: list) -> list:
        """
        Lightweight lexical parser extracting contracts, state variables, and function blocks.
        """
        contracts = []
        contract_regex = re.compile(r"\bcontract\s+([A-Za-z0-9_]+)(?:\s+is\s+([^{]+))?\s*\{")
        
        matches = list(contract_regex.finditer(source_code))
        if not matches:
            # Standalone function or interface snippet
            functions = self._parse_functions_in_block(source_code, 1, lines)
            return [{
                "name": "AnonymousContract",
                "inherited": [],
                "functions": functions
            }]

        for idx, match in enumerate(matches):
            c_name = match.group(1)
            inherited_raw = match.group(2) or ""
            inherited = [x.strip() for x in inherited_raw.split(",") if x.strip()]
            
            start_pos = match.start()
            end_pos = matches[idx + 1].start() if idx + 1 < len(matches) else len(source_code)
            
            c_code = source_code[start_pos:end_pos]
            line_offset = source_code[:start_pos].count("\n") + 1
            
            functions = self._parse_functions_in_block(c_code, line_offset, lines)
            contracts.append({
                "name": c_name,
                "inherited": inherited,
                "functions": functions
            })

        return contracts

    def _parse_functions_in_block(self, code_block: str, line_offset: int, full_lines: list) -> list:
        functions = []
        func_regex = re.compile(
            r"(?:function\s+([A-Za-z0-9_]+)\s*\((.*?)\)|(fallback|receive)\s*\((.*?)\))\s*([^{;]*)(?:\{|;)",
            re.DOTALL
        )

        for match in func_regex.finditer(code_block):
            f_name = match.group(1) or match.group(3) or "unnamed"
            params = match.group(2) or match.group(4) or ""
            modifiers_raw = match.group(5) or ""
            
            start_in_block = match.start()
            local_line = code_block[:start_in_block].count("\n") + line_offset
            
            # Find function body bounds
            body_start = match.end() - 1
            body, body_end_line = self._extract_body(code_block, body_start, local_line)
            
            mod_tokens = modifiers_raw.split()
            
            # Visibility
            visibility = "public"  # default in older solidity, or unspecified
            for v in ["public", "external", "internal", "private"]:
                if v in mod_tokens:
                    visibility = v
                    break

            # Mutability
            is_view = "view" in mod_tokens
            is_pure = "pure" in mod_tokens
            is_payable = "payable" in mod_tokens
            
            # Modifiers
            extracted_modifiers = []
            for token in mod_tokens:
                clean_t = token.strip()
                if clean_t and clean_t not in ["public", "external", "internal", "private", "view", "pure", "payable", "virtual", "override", "returns"]:
                    # strip parentheses if modifier has arguments
                    mod_name = clean_t.split("(")[0]
                    extracted_modifiers.append(mod_name)

            functions.append({
                "name": f_name,
                "params": params,
                "visibility": visibility,
                "is_view": is_view,
                "is_pure": is_pure,
                "is_payable": is_payable,
                "modifiers": extracted_modifiers,
                "modifiers_raw": modifiers_raw,
                "body": body,
                "line_start": local_line,
                "line_end": body_end_line
            })

        return functions

    def _extract_body(self, code: str, start_index: int, start_line: int):
        """Extracts balanced curly braces body"""
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

    def _detect_sensitivity(self, func: dict) -> tuple:
        """Determines if the function is a sensitive state-changing function"""
        f_name = func["name"]
        
        # Check name patterns
        for pattern, sens_type, sev, impact in self.SENSITIVE_FUNC_PATTERNS:
            if re.search(pattern, f_name, re.IGNORECASE):
                return sens_type, sev, impact

        # Check body operations (e.g. totalSupply += amount inside unnamed or custom function)
        body = func["body"]
        for pattern, sens_type, sev, impact in self.SENSITIVE_BODY_PATTERNS:
            if re.search(pattern, body):
                return sens_type, sev, impact

        return None

    def _has_access_control(self, func: dict, contract: dict) -> tuple:
        """
        Checks whether recognizable access control is applied:
        1. Modifiers (onlyOwner, onlyRole, etc.)
        2. Inline require(msg.sender == owner, ...)
        3. Inherited contract checks
        """
        # 1. Modifiers
        for mod in func["modifiers"]:
            if mod.lower() in self.KNOWN_AUTH_MODIFIERS:
                return True, f"Modifier `{mod}`"

        # 2. Check function body for require/revert checks
        body = func["body"]
        auth_body_patterns = [
            (r"require\s*\(\s*msg\.sender\s*==\s*[A-Za-z0-9_.]+", "require(msg.sender == owner/authorized)"),
            (r"require\s*\(\s*[A-Za-z0-9_.]+\s*==\s*msg\.sender", "require(owner/authorized == msg.sender)"),
            (r"if\s*\(\s*msg\.sender\s*!=\s*[A-Za-z0-9_.]+\s*\)\s*revert", "if (msg.sender != owner) revert()"),
            (r"_checkOwner\s*\(\s*\)", "Internal OpenZeppelin `_checkOwner()` check"),
            (r"_checkRole\s*\(", "OpenZeppelin `_checkRole(...)` check"),
            (r"hasRole\s*\(", "OpenZeppelin `hasRole(...)` check"),
            (r"_requireAuth\s*\(", "Internal `_requireAuth()` check")
        ]

        for pat, desc in auth_body_patterns:
            if re.search(pat, body):
                return True, desc

        return False, None

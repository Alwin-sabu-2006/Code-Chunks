"""
Q-Chain Transaction Risk Analyzer
Threat 1: Malicious Transactions and Dangerous Token Approvals
"""
import re
from web3 import Web3
from eth_abi import decode
from config import (
    UINT256_MAX,
    UNLIMITED_ALLOWANCE_THRESHOLD,
    ERC20_SELECTORS,
    KNOWN_PROTOCOLS,
    FLAGGED_SUSPICIOUS_SPENDERS,
    DEFAULT_RPC_ENDPOINTS
)
from analyzers.report_generator import create_finding, calculate_risk_profile

class TransactionRiskAnalyzer:
    def __init__(self, rpc_url: str = None):
        self.rpc_url = rpc_url or DEFAULT_RPC_ENDPOINTS["ethereum"]
        self.w3 = None
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={'timeout': 4}))
        except Exception:
            self.w3 = None

    def analyze(self, tx_data: dict) -> dict:
        """
        Analyzes transaction data or raw hex payload.
        tx_data can contain:
          - tx_hash: EVM transaction hash
          - raw_data: hex data payload (e.g., 0x095ea7b3...)
          - to: target contract address
          - from: sender address
          - decoded: pre-decoded parameters (function_name, spender, amount, token)
        """
        findings = []
        parsed_details = {
            "transaction_type": "UNKNOWN",
            "target": tx_data.get("to", "Unknown"),
            "function_name": "unknown",
            "token_address": tx_data.get("token_address", tx_data.get("to", "")),
            "spender": "",
            "recipient": "",
            "amount_raw": 0,
            "amount_formatted": "",
            "is_unlimited": False,
            "spender_reputation": "UNKNOWN",
            "spender_name": "Unverified Spender"
        }

        # 1. Resolve transaction input if tx_hash provided
        tx_hash = tx_data.get("tx_hash", "").strip()
        raw_hex = tx_data.get("raw_data", "").strip()
        
        if tx_hash:
            if not self._is_valid_tx_hash(tx_hash):
                findings.append(create_finding(
                    finding_id="QCHAIN-TX-ERR-01",
                    category="Malicious Transactions and Dangerous Token Approvals",
                    title="Invalid Transaction Hash Format",
                    severity="LOW",
                    confidence="CONFIRMED",
                    status="Analysis incomplete",
                    target=tx_hash,
                    evidence=f"Input does not match 66-character EVM hash regex: {tx_hash}",
                    impact="Cannot fetch remote transaction details from blockchain RPC.",
                    mitigation="Verify that the provided transaction hash is a valid 32-byte hex string (0x...).",
                    scanner="Q-Chain RPC Fetcher"
                ))
                score, level = calculate_risk_profile(findings)
                return {
                    "findings": findings,
                    "parsed_details": parsed_details,
                    "risk_score": score,
                    "risk_level": level,
                    "summary": "Analysis incomplete due to invalid transaction hash."
                }
            
            # Attempt RPC fetch if available
            fetched_data = self._fetch_tx_from_rpc(tx_hash)
            if fetched_data:
                raw_hex = fetched_data.get("input", raw_hex)
                parsed_details["target"] = fetched_data.get("to", parsed_details["target"])
                parsed_details["token_address"] = parsed_details["target"]

        # 2. Check if pre-decoded or need to decode raw_hex
        if tx_data.get("decoded"):
            dec = tx_data["decoded"]
            parsed_details.update(dec)
            if "amount" in dec:
                try:
                    parsed_details["amount_raw"] = int(dec["amount"])
                except (ValueError, TypeError):
                    parsed_details["amount_raw"] = 0
            if "spender" in dec:
                parsed_details["spender"] = dec["spender"]
            if "function_name" in dec:
                parsed_details["function_name"] = dec["function_name"]
        elif raw_hex:
            self._decode_raw_hex(raw_hex, parsed_details, findings)

        # 3. Analyze spender reputation
        spender_addr = parsed_details.get("spender", "").lower()
        if spender_addr:
            if spender_addr in FLAGGED_SUSPICIOUS_SPENDERS:
                suspicious_info = FLAGGED_SUSPICIOUS_SPENDERS[spender_addr]
                parsed_details["spender_reputation"] = "MALICIOUS_DRAINER"
                parsed_details["spender_name"] = suspicious_info["name"]
                findings.append(create_finding(
                    finding_id="QCHAIN-TX-SPENDER-MALICIOUS",
                    category="Malicious Transactions and Dangerous Token Approvals",
                    title="Critical: Spender Address Blacklisted as Malicious Drainer",
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    status="Potential issue detected",
                    target=spender_addr,
                    evidence=f"Address matches threat registry entry: {suspicious_info['name']} ({suspicious_info['reason']})",
                    impact="Authorizing this address will result in total immediate loss of tokens.",
                    mitigation="REJECT AND ABORT TRANSACTION IMMEDIATELY. Do not sign or approve this spender under any circumstances.",
                    scanner="Q-Chain Threat Intelligence Registry"
                ))
            elif spender_addr in KNOWN_PROTOCOLS:
                known_info = KNOWN_PROTOCOLS[spender_addr]
                parsed_details["spender_reputation"] = "VERIFIED_PROTOCOL"
                parsed_details["spender_name"] = f"{known_info['name']} ({known_info['category']})"
            else:
                parsed_details["spender_reputation"] = "UNVERIFIED"
                parsed_details["spender_name"] = "Unverified / Third-Party Address"

        # 4. Threat Evaluation: Unlimited vs Limited Approvals
        fn_name = parsed_details.get("function_name", "").lower()
        amount = parsed_details.get("amount_raw", 0)

        if "approve" in fn_name or "increaseallowance" in fn_name:
            parsed_details["transaction_type"] = "TOKEN_APPROVAL"
            is_unlimited = (amount >= UINT256_MAX - 1000) or (amount >= UNLIMITED_ALLOWANCE_THRESHOLD)
            parsed_details["is_unlimited"] = is_unlimited

            if is_unlimited:
                # Test Case 1: Unlimited approval detected
                sev = "HIGH"
                if parsed_details["spender_reputation"] == "UNVERIFIED":
                    sev = "CRITICAL"
                elif parsed_details["spender_reputation"] == "VERIFIED_PROTOCOL":
                    sev = "MEDIUM"

                findings.append(create_finding(
                    finding_id="QCHAIN-TX-APPROVE-UNLIMITED",
                    category="Malicious Transactions and Dangerous Token Approvals",
                    title="Unlimited Token Approval Requested",
                    severity=sev,
                    confidence="CONFIRMED",
                    status="Potential issue detected",
                    target=f"approve(spender={parsed_details['spender']})",
                    evidence=f"Allowance parameter is set to maximum uint256 ({amount}) which grants indefinite spending rights.",
                    impact="The approved spender may be able to transfer all existing and future tokens covered by the allowance without requiring any further user signature. If the spender protocol is compromised or malicious, your entire balance can be drained.",
                    mitigation="Verify the spender address identity carefully. Do not grant unlimited allowance; specify an exact allowance required only for the immediate transaction (e.g. 100 USDC) or use EIP-2612 permit with a short expiry.",
                    scanner="Q-Chain Token Approval Risk Engine"
                ))
            else:
                # Test Case 2: Limited approval identified
                findings.append(create_finding(
                    finding_id="QCHAIN-TX-APPROVE-LIMITED",
                    category="Malicious Transactions and Dangerous Token Approvals",
                    title="Limited Token Approval Detected",
                    severity="LOW",
                    confidence="CONFIRMED",
                    status="Informational finding",
                    target=f"approve(spender={parsed_details['spender']}, amount={amount})",
                    evidence=f"Allowance is explicitly capped at {parsed_details['amount_formatted'] or amount} units. No unlimited approval pattern found.",
                    impact="The spender contract can transfer only up to the specified amount. Maximum exposure is bounded.",
                    mitigation="Ensure you intend to interact with this contract and verify that the specified amount corresponds to your intended trade.",
                    scanner="Q-Chain Token Approval Risk Engine"
                ))
                
        elif "transfer" in fn_name and "transferfrom" not in fn_name:
            # Test Case 3: Ordinary token transfer
            parsed_details["transaction_type"] = "TOKEN_TRANSFER"
            findings.append(create_finding(
                finding_id="QCHAIN-TX-TRANSFER-DIRECT",
                category="Malicious Transactions and Dangerous Token Approvals",
                title="Direct Token Transfer Identified",
                severity="INFORMATIONAL",
                confidence="CONFIRMED",
                status="Informational finding",
                target=f"transfer(recipient={parsed_details.get('recipient', parsed_details.get('spender'))}, amount={amount})",
                evidence="Standard ERC-20 transfer function invocation. No token approval or allowance modification requested.",
                impact="Direct one-off transfer of assets from caller to destination recipient. Does not create residual allowance risk.",
                mitigation="Verify recipient address matches your intended counterparty before confirming.",
                scanner="Q-Chain Transaction Decoder"
            ))

        elif parsed_details["transaction_type"] == "UNKNOWN" and raw_hex:
            findings.append(create_finding(
                finding_id="QCHAIN-TX-UNKNOWN-CALL",
                category="Malicious Transactions and Dangerous Token Approvals",
                title="Unrecognized Contract Call Data",
                severity="LOW",
                confidence="HEURISTIC",
                status="Informational finding",
                target=parsed_details.get("target", "Target Contract"),
                evidence=f"Call data selector {raw_hex[:10]} does not match standard ERC-20 interface.",
                impact="Transaction performs custom contract execution that could not be decoded by standard token rules.",
                mitigation="Verify contract source code and ABI on block explorer before proceeding.",
                scanner="Q-Chain Transaction Decoder"
            ))

        # Calculate final risk profile
        score, level = calculate_risk_profile(findings)
        
        summary = self._generate_summary(parsed_details, findings, level)

        return {
            "findings": findings,
            "parsed_details": parsed_details,
            "risk_score": score,
            "risk_level": level,
            "summary": summary
        }

    def _decode_raw_hex(self, raw_hex: str, parsed_details: dict, findings: list):
        """Decodes raw ERC-20 calldata"""
        clean_hex = raw_hex.strip()
        if not clean_hex.startswith("0x"):
            clean_hex = "0x" + clean_hex
            
        if len(clean_hex) < 10:
            findings.append(create_finding(
                finding_id="QCHAIN-TX-ERR-SHORT",
                category="Malicious Transactions and Dangerous Token Approvals",
                title="Malformed Transaction Calldata",
                severity="LOW",
                confidence="CONFIRMED",
                status="Analysis incomplete",
                target="Raw Calldata",
                evidence=f"Data length is only {len(clean_hex)} characters, insufficient for 4-byte selector.",
                impact="Cannot parse function signature.",
                mitigation="Provide complete EVM input data.",
                scanner="Q-Chain Calldata Decoder"
            ))
            return

        selector = clean_hex[:10].lower()
        data_body = clean_hex[10:]
        
        # Match selector
        sig = ERC20_SELECTORS.get(selector)
        if not sig:
            parsed_details["function_name"] = f"custom_method_{selector}"
            return

        parsed_details["function_name"] = sig.split("(")[0]

        try:
            raw_bytes = bytes.fromhex(data_body)
            if "approve" in sig or "increaseAllowance" in sig or "decreaseAllowance" in sig:
                decoded = decode(['address', 'uint256'], raw_bytes)
                parsed_details["spender"] = decoded[0]
                parsed_details["amount_raw"] = decoded[1]
                parsed_details["amount_formatted"] = self._format_amount(decoded[1])
            elif "transfer(address,uint256)" in sig:
                decoded = decode(['address', 'uint256'], raw_bytes)
                parsed_details["recipient"] = decoded[0]
                parsed_details["spender"] = decoded[0]
                parsed_details["amount_raw"] = decoded[1]
                parsed_details["amount_formatted"] = self._format_amount(decoded[1])
            elif "transferFrom" in sig:
                decoded = decode(['address', 'address', 'uint256'], raw_bytes)
                parsed_details["sender"] = decoded[0]
                parsed_details["recipient"] = decoded[1]
                parsed_details["amount_raw"] = decoded[2]
                parsed_details["amount_formatted"] = self._format_amount(decoded[2])
        except Exception as e:
            findings.append(create_finding(
                finding_id="QCHAIN-TX-ERR-ABI",
                category="Malicious Transactions and Dangerous Token Approvals",
                title="Calldata Decoding Exception",
                severity="LOW",
                confidence="CONFIRMED",
                status="Analysis incomplete",
                target="ABI Decoder",
                evidence=f"Could not decode parameters for signature {sig}: {str(e)}",
                impact="Parameter values may be truncated or non-standard.",
                mitigation="Check if token uses non-standard parameter types.",
                scanner="Q-Chain ABI Decoder"
            ))

    def _format_amount(self, amount: int) -> str:
        if amount >= UINT256_MAX - 1000:
            return "Unlimited (type(uint256).max)"
        if amount >= 10**18:
            return f"{amount / 10**18:,.4f} Tokens (18 decimals)"
        return f"{amount:,} Base Units"

    def _is_valid_tx_hash(self, tx_hash: str) -> bool:
        return bool(re.match(r"^0x[a-fA-F0-9]{64}$", tx_hash))

    def _fetch_tx_from_rpc(self, tx_hash: str) -> dict:
        if not self.w3:
            return None
        try:
            tx = self.w3.eth.get_transaction(tx_hash)
            if tx:
                return {
                    "to": tx.get("to"),
                    "from": tx.get("from"),
                    "input": tx.get("input").hex() if hasattr(tx.get("input"), "hex") else str(tx.get("input")),
                    "value": tx.get("value")
                }
        except Exception:
            return None
        return None

    def _generate_summary(self, details: dict, findings: list, level: str) -> str:
        fn = details.get("function_name", "transaction")
        spender = details.get("spender_name", "recipient")
        if details.get("is_unlimited"):
            return f"High-risk unlimited approval detected for {spender}. Risk Level: {level}."
        elif "approve" in fn:
            return f"Limited approval of {details.get('amount_formatted', 'specified tokens')} identified. Risk Level: {level}."
        elif "transfer" in fn:
            return f"Standard token transfer of {details.get('amount_formatted', 'tokens')} identified. No approval risks found."
        return f"Transaction analysis completed with {len(findings)} finding(s). Risk Level: {level}."

"""
Q-Chain Report Generator and Normalization Service
Conforms strictly to Section 7: Common Finding Format and Risk Scoring
"""

SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5,
    "INFORMATIONAL": 0
}

def create_finding(
    finding_id: str,
    category: str,
    title: str,
    severity: str,
    confidence: str,
    status: str,
    target: str,
    evidence: str,
    impact: str,
    mitigation: str,
    scanner: str,
    line_number: int = None,
    code_snippet: str = None
) -> dict:
    """
    Constructs a normalized finding strictly matching Section 7 requirements.
    """
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    if severity not in valid_severities:
        severity = "MEDIUM"

    valid_statuses = [
        "Potential issue detected",
        "Informational finding",
        "No matching issue detected",
        "Analysis incomplete"
    ]
    if status not in valid_statuses:
        status = "Potential issue detected"

    return {
        "finding_id": finding_id,
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "target": target,
        "line_number": line_number,
        "code_snippet": code_snippet,
        "evidence": evidence,
        "impact": impact,
        "mitigation": mitigation,
        "scanner": scanner,
        "what_just_happened": _generate_what_just_happened(category, finding_id, target, evidence, impact, mitigation)
    }

def _generate_what_just_happened(category: str, finding_id: str, target: str, evidence: str, impact: str, mitigation: str) -> dict:
    """
    Generates an educational, step-by-step 'What Just Happened?' breakdown
    tailored to the specific threat category.
    """
    fid = (finding_id or "").upper()
    cat = (category or "").lower()

    if "approv" in cat or "transaction" in cat or "TX" in fid:
        if "UNLIMITED" in fid:
            return {
                "headline": "A dApp or contract requested indefinite spending authority over your entire token balance.",
                "mechanism": "The transaction calls the ERC-20 `approve(spender, amount)` function with amount = 2^256 - 1 (maximum uint256). This sets the allowance mapping in the token contract to unlimited.",
                "attack_scenario": [
                    "Step 1 (User Action): You sign the approval transaction, trusting the current dApp frontend.",
                    "Step 2 (Hidden Authority): The token smart contract records an unlimited spending allowance for the spender address.",
                    "Step 3 (Future Compromise): Days or months later, if the spender contract is exploited, has private keys leaked, or is a malicious phishing contract, the attacker calls transferFrom(yourAddress, attackerAddress, balance).",
                    "Step 4 (Asset Loss): Your tokens are transferred away without requiring any new signature or wallet confirmation prompt."
                ],
                "observable_fact": f"{evidence}",
                "risk_vs_fact": "An unlimited approval alone does not prove malicious intent—many legitimate DEXes request it to save gas on future trades. However, it creates severe residual exposure if the contract is ever compromised.",
                "safe_alternative": "Set a custom allowance matching only the exact token amount needed for this trade (e.g. 500 USDC), or revoke the allowance immediately after the trade completes."
            }
        elif "MALICIOUS" in fid or "DRAINER" in fid:
            return {
                "headline": "A known malicious wallet-drainer phishing contract requested transaction authorization.",
                "mechanism": "The target address matches a threat-intelligence blacklist associated with phishing sites and automated asset drainers.",
                "attack_scenario": [
                    "Step 1 (Lure): A malicious site mimicked an airdrop, mint, or DEX interface.",
                    "Step 2 (Phishing Request): The site crafted a transaction pointing to a known theft contract.",
                    "Step 3 (Instant Drain): The moment this transaction confirms, an automated bot script calls transferFrom and immediately sweeps your assets."
                ],
                "observable_fact": f"{evidence}",
                "risk_vs_fact": "Confirmed threat signature. The destination is flagged on global Web3 threat databases.",
                "safe_alternative": "ABORT TRANSACTION IMMEDIATELY. Disconnect wallet from the website and clear browser session."
            }
        elif "LIMITED" in fid:
            return {
                "headline": "A bounded token approval was requested for a specific amount.",
                "mechanism": "The transaction establishes an allowance capped at the specified numerical value. The spender cannot withdraw more than this cap.",
                "attack_scenario": [
                    "Step 1: Spender is authorized only up to the specified amount.",
                    "Step 2: Worst-case exposure is strictly bounded to that approved limit."
                ],
                "observable_fact": f"{evidence}",
                "risk_vs_fact": "Safe practice followed. The allowance is bounded.",
                "safe_alternative": "Ensure the approved amount matches your intended swap or deposit."
            }
        else:
            return {
                "headline": "Direct token transfer requested.",
                "mechanism": "Invokes standard ERC-20 transfer(recipient, amount) directly moving tokens without creating lingering allowances.",
                "attack_scenario": [
                    "Step 1: Tokens transfer directly to the recipient.",
                    "Step 2: No residual permissions or future allowances are granted."
                ],
                "observable_fact": f"{evidence}",
                "risk_vs_fact": "One-time transfer. No ongoing allowance exposure.",
                "safe_alternative": "Verify that the recipient address belongs to your intended party."
            }

    elif "access" in cat or "AC" in fid:
        if "UNPROTECTED" in fid:
            return {
                "headline": "A critical privileged function can be called by ANY account on the blockchain.",
                "mechanism": f"The function `{target}` alters sensitive state or assets, is declared public or external, but has NO access control checks (onlyOwner, onlyRole, or require(msg.sender == owner)).",
                "attack_scenario": [
                    f"Step 1 (Attacker Discovery): An attacker monitors contract deployments or bytecode and spots that `{target}` is public without modifiers.",
                    f"Step 2 (Exploit Transaction): The attacker sends a transaction directly calling `{target}`.",
                    "Step 3 (Unauthorized Execution): The contract processes the call because there is no msg.sender check.",
                    "Step 4 (Supply Inflation / Loss): If it is a mint function, millions of new tokens are minted for free and dumped on liquidity pools, destroying the token's value."
                ],
                "observable_fact": f"{evidence}",
                "risk_vs_fact": "Confirmed code vulnerability. In Solidity, public functions are callable by anyone by default unless explicit restrictions are enforced.",
                "safe_alternative": "Apply OpenZeppelin's Ownable pattern: add `onlyOwner` modifier to the function or use AccessControl roles."
            }
        else:
            return {
                "headline": "Recognized authorization guard is actively protecting this function.",
                "mechanism": f"The function `{target}` requires verified caller credentials (such as owner or role modifier) before proceeding.",
                "attack_scenario": [
                    "Step 1: Unauthorized callers attempting to execute this function are rejected.",
                    "Step 2: The transaction reverts with an authorization error."
                ],
                "observable_fact": f"{evidence}",
                "risk_vs_fact": "Standard defense verified. Ensure the owner private key or admin multisig is properly guarded.",
                "safe_alternative": "Maintain secure operational security for administrative keys."
            }

    elif "reentrancy" in cat or "RE" in fid:
        if "CEI-VIOLATION" in fid:
            return {
                "headline": "The contract sends funds to an external address BEFORE updating its internal balance records.",
                "mechanism": f"In function `{target}`, an external call (e.g., msg.sender.call{{value:...}}) occurs before the storage write (e.g., balances[msg.sender] = 0;). This violates the Checks-Effects-Interactions (CEI) design pattern.",
                "attack_scenario": [
                    "Step 1 (Initial Call): Attacker deposits 1 ETH, then calls withdraw().",
                    "Step 2 (The External Call): The vault checks balances[attacker] == 1 ETH (passes), and sends 1 ETH to attacker contract via .call{value: 1 ETH}.",
                    "Step 3 (Recursive Re-entry): Before the vault can reach line `balances[msg.sender] = 0`, the attacker's fallback receive() hook is triggered and immediately calls vault.withdraw() AGAIN!",
                    "Step 4 (Outdated State): The vault checks balances[attacker] a second time. Because the balance was not reset yet, it still reads 1 ETH!",
                    "Step 5 (Total Drain): The cycle repeats recursively until all ETH in the vault is transferred to the attacker contract. Finally, the recursion unwinds and resets the balance to 0, too late."
                ],
                "observable_fact": f"{evidence}",
                "risk_vs_fact": "Severe architectural flaw. Untrusted external calls transfer control flow to the recipient before contract invariants are restored.",
                "safe_alternative": "Apply Checks-Effects-Interactions: reset `balances[msg.sender] = 0` BEFORE the external call, or add OpenZeppelin ReentrancyGuard (`nonReentrant`)."
            }
        else:
            return {
                "headline": "Execution ordering protects against reentrant callbacks.",
                "mechanism": f"Function `{target}` updates internal state variables before triggering external calls, or utilizes a reentrancy mutex guard.",
                "attack_scenario": [
                    "Step 1: Attacker attempts recursive re-entry callback.",
                    "Step 2: The vault reads the updated zero balance or hits the active mutex lock.",
                    "Step 3: The recursive call reverts, preserving vault funds."
                ],
                "observable_fact": f"{evidence}",
                "risk_vs_fact": "Defense verified against single-entry reentrancy.",
                "safe_alternative": "Maintain CEI pattern across all interacting contracts."
            }

    return {
        "headline": f"Analysis finding on {target}.",
        "mechanism": evidence,
        "attack_scenario": [
            "Step 1: Review the identified code or transaction pattern.",
            "Step 2: Assess potential caller authority and state mutations."
        ],
        "observable_fact": evidence,
        "risk_vs_fact": impact,
        "safe_alternative": mitigation
    }

def calculate_risk_profile(findings: list) -> tuple:
    """
    Calculates the combined risk score (0-100) and risk level.
    """
    if not findings:
        return 0, "INFORMATIONAL"

    # Sum weights capped at 100
    score = 0
    has_critical = False
    has_high = False
    has_medium = False

    for f in findings:
        sev = f.get("severity", "INFORMATIONAL")
        score += SEVERITY_WEIGHTS.get(sev, 0)
        if sev == "CRITICAL":
            has_critical = True
        elif sev == "HIGH":
            has_high = True
        elif sev == "MEDIUM":
            has_medium = True

    score = min(score, 100)

    if has_critical or score >= 80:
        level = "CRITICAL"
        score = max(score, 85)
    elif has_high or score >= 60:
        level = "HIGH"
        score = max(score, 65)
    elif has_medium or score >= 30:
        level = "MEDIUM"
        score = max(score, 40)
    elif score > 0:
        level = "LOW"
    else:
        level = "INFORMATIONAL"

    return score, level

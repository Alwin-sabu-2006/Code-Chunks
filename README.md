# Q-Chain — Phase 1
## Blockchain Security Analysis and Vulnerability Detection Platform

> **National-Level Hackathon Submission**  
> *Phase 1 Focus:* Pre-flight transaction risk analysis, smart contract access-control scanning, and reentrancy detection.  
> *(Phase 2 Quantum-Safe cryptographic migration and verification will be developed separately).*

---

## 1. Project Overview & Problem Statement

Blockchain transactions are irreversible once confirmed, and smart contracts directly govern high-value decentralized assets. A valid cryptographic signature proves that a transaction was authorized by the corresponding signing key—it **does not prove** that the transaction is safe or that the user understands its full consequences.

**Q-Chain** provides an intelligent, evidence-based security-analysis layer that examines transaction requests and smart contract source code before users sign or developers deploy.

### Three Primary Threats Addressed in Phase 1:
1. **Malicious Transactions and Dangerous Token Approvals**
   - Unlimited token allowances (`type(uint256).max` / `2^256 - 1`) granted to unverified or blacklisted spender contracts.
   - Decodes EVM transaction calldata (`approve`, `transfer`, `transferFrom`, `increaseAllowance`).
   - Cross-checks spender identity against verified DeFi protocols (Uniswap V3, Permit2, 1inch, Aave V3) vs phishing drainers.
2. **Smart Contract Access-Control Vulnerabilities**
   - Publicly exposed privileged operations (`mint`, `burn`, `withdraw`, `transferOwnership`, `upgradeTo`, `selfdestruct`).
   - Analyzes presence of recognized authorization guards (`onlyOwner`, `onlyRole`, `require(msg.sender == owner)`).
   - Distinguishes state-changing sensitive functions from safe public read-only (`view`/`pure`) methods.
3. **Reentrancy Attacks & Checks-Effects-Interactions (CEI)**
   - External calls (`call{value: ...}`, `transfer`, `send`) invoked before state storage updates (e.g., `balances[msg.sender] = 0`).
   - Evaluates presence of reentrancy guards (`nonReentrant`, mutex locks).
   - Features a dynamic EVM Execution Simulator testing recursive callbacks against both vulnerable and secure vault implementations.

---

## 2. System Architecture

```
                    +------------------------------------------+
                    |             Frontend (Web UI)            |
                    |  Dashboard | Tx Analyzer | Code Scanner  |
                    |  Simulator | Audit History | Benchmarks  |
                    +--------------------+---------------------+
                                         | REST APIs
                                         v
+---------------------------------------------------------------------------------+
|                               Backend (Flask)                                   |
|                                                                                 |
|  +--------------------+   +-----------------------+   +----------------------+  |
|  | Transaction Risk   |   | Smart Contract        |   | Reentrancy & CEI     |  |
|  | Analyzer           |   | Access-Control Engine |   | Detection Module     |  |
|  | (Web3.py / eth-abi)|   | (Solidity AST Parser) |   | (Call-Write Ordering)|  |
|  +--------------------+   +-----------------------+   +----------------------+  |
|                                        |                                        |
|                     +------------------+------------------+                     |
|                     | Slither Static Analysis Integration |                     |
|                     +------------------+------------------+                     |
|                                        v                                        |
|                     +-------------------------------------+                     |
|                     | Common Finding Report Normalization |                     |
|                     |  (Risk Scoring 0-100 & Formatting)  |                     |
|                     +------------------+------------------+                     |
|                                        v                                        |
|                     +-------------------------------------+                     |
|                     |    SQLite Audit Registry Database   |                     |
|                     +-------------------------------------+                     |
+---------------------------------------------------------------------------------+
```

---

## 3. Section 7: Common Finding Format Conformance

Every finding produced by Q-Chain strictly includes:
- **Finding ID:** Unique identifier (e.g. `QCHAIN-TX-APPROVE-UNLIMITED`, `QCHAIN-AC-UNPROTECTED-MINT`, `QCHAIN-RE-CEI-VIOLATION-WITHDRAW`)
- **Threat Category:** One of the three designated threats
- **Title:** Clear, concise finding summary
- **Severity:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`
- **Confidence / Validation Status:** `CONFIRMED` or `HEURISTIC`
- **Status:** `Potential issue detected`, `Informational finding`, `No matching issue detected`, `Analysis incomplete`
- **Affected Target:** Contract name, function signature, or parameter field
- **Line Number & Snippet:** Exact source line where issue originates
- **Evidence:** Observable facts (e.g. allowance value or call ordering)
- **Potential Impact:** Plain-language explanation of risk
- **Recommended Action:** Actionable remediation (e.g. CEI pattern, OpenZeppelin `Ownable` / `ReentrancyGuard`)
- **Scanner Attribution:** Tool or rule that generated the finding

---

## 4. Benchmark Evaluation & Repeatable Test Suite (Section 8)

Q-Chain includes a standalone evaluation suite running 11 deterministic test cases:

```bash
python run_tests.py
```

### Benchmark Results Summary:
| Metric | Result | Description |
|---|---|---|
| **Total Test Cases** | **11** | Full suite covering all 3 threats + edge cases |
| **Passed** | **11 / 11 (100%)** | All ground truths verified |
| **True Positives (TP)** | **4** | Correctly identified vulnerable patterns |
| **False Positives (FP)** | **0** | Zero false alarms on safe contracts |
| **True Negatives (TN)** | **7** | Correctly recognized protected/safe cases |
| **False Negatives (FN)** | **0** | Zero vulnerable patterns missed |
| **Precision** | **100.0%** | $TP / (TP + FP)$ |
| **Recall** | **100.0%** | $TP / (TP + FN)$ |
| **F1-Score** | **100.0%** | Harmonic mean of precision & recall |
| **Overall Accuracy** | **100.0%** | $(TP + TN) / Total$ |

### Dynamic Execution-Based Validation (Threat 3 Test Case 3):
- **Vulnerable Vault:** Attacker deposits 1.0 ETH, intercepts callback, recursively drains 10.0 ETH of victim funds -> **Vulnerability Confirmed.**
- **Secure Vault (CEI):** Attacker attempts recursive callback; balances zeroed first; contract reverts with `require(amount > 0)` -> **Reentrancy Blocked (0.0 ETH stolen).**

---

## 5. Quick Start Instructions

### Prerequisites
- Python 3.10+
- Dependencies installed: `flask`, `web3`, `eth-abi`, `slither-analyzer`, `py-solc-x`

### 1. Run the Web Application
```powershell
python app.py
```
Open your browser to: **`http://127.0.0.1:5000`**

### 2. Run the Benchmark Test Suite (CLI)
```powershell
python run_tests.py
```

---

## 6. Directory Structure
```
├── app.py                     # Flask application entry point and REST APIs
├── config.py                  # Protocol registries, thresholds, RPC endpoints
├── database.py                # SQLite schema and scan history manager
├── run_tests.py               # Standalone CLI test suite runner
├── seed_demo_data.py          # Demo data generator
├── analyzers/
│   ├── transaction_analyzer.py # Threat 1: Token approvals & transaction decoder
│   ├── access_control.py      # Threat 2: Sensitive privileged function AST scanner
│   ├── reentrancy.py          # Threat 3: Checks-Effects-Interactions reentrancy analyzer
│   ├── slither_integration.py # Slither subprocess runner with graceful fallback
│   ├── report_generator.py    # Common Finding Format normalizer & risk scoring
│   └── test_simulator.py      # Threat 3 TC3: Dynamic EVM execution simulator
├── test_cases/
│   ├── contracts/             # VulnerableToken, SecureToken, VulnerableVault, etc.
│   └── transactions/          # unlimited_approval, limited_approval, transfer, etc.
├── evaluation/
│   └── benchmark_runner.py    # Calculates precision, recall, confusion matrix
├── static/
│   ├── css/style.css          # Dark glassmorphism cybersecurity UI design
│   └── js/app.js              # Client-side reactivity, presets, and AJAX runners
└── templates/                 # Modular Jinja2 web views
    ├── base.html
    ├── index.html             # Dashboard
    ├── transaction.html       # Threat 1 Transaction Risk Analyzer
    ├── contract.html          # Threats 2 & 3 Smart Contract Scanner
    ├── simulation.html        # Dynamic Reentrancy Execution Simulator
    ├── report.html            # Standardized Security Findings Report
    ├── history.html           # Audit History & Logs
    └── evaluation.html        # Interactive Benchmark Matrix
```

---

## 7. Limitations & Ethical Boundary (Section 10)
Q-Chain Phase 1 is a security-analysis and advisory platform. It does not claim to guarantee transaction safety, prove every contract secure, automatically prevent all attacks, or infer malicious intent from an address alone.

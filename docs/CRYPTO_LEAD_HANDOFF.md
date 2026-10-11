# Q-Chain: Member 1 (Crypto & PQC Lead) Integration & Handoff Guide

> **Delivered by:** Member 1 (Crypto & PQC Lead)  
> **Target Roles:** Member 2 (AI/Agents), Member 3 (Backend/MCP), Member 4 (Blockchain/Scanner), Member 5 (Frontend/Voice)

---

## 1. Overview of Delivered Assets

As Crypto and PQC Lead, I have built and verified the complete cryptographic engine for Q-Chain:

1. **Docker Environment (`docker/Dockerfile.crypto` & `docker/docker-compose.crypto.yml`):**
   - Containerized build with `liboqs` C shared library, `liboqs-python`, OpenSSL 3, Python 3.11, and pure-Python reference fallback.
2. **Crypto Engine (`crypto/`):**
   - Classical baseline: `ECDSASecp256k1Signer` (secp256k1 standard).
   - NIST FIPS 204: `MLDSASigner` (ML-DSA-44, ML-DSA-65, ML-DSA-87).
   - NIST FIPS 205: `SLHDSASigner` (SLH-DSA-SHAKE-128f, 128s, 256f).
   - Draft FN-DSA: `FalconSigner` (Falcon-512, Falcon-1024).
   - Hybrid Dual-Signer: `HybridECDSAMLDSASigner` (ECDSA + ML-DSA dual scheme).
   - Central Registry: `CryptoRegistry`.
3. **Statistical Benchmark Harness (`crypto/benchmark.py`):**
   - Nanosecond timing collection with warm-up, statistical variance (mean & std_dev), size footprints, and EVM gas calculations.
4. **Tamper Verification Suite (`crypto/verification.py`):**
   - 4-scenario adversarial matrix (valid, 1-bit flipped in message, 1-bit flipped in signature, wrong public key) achieving 100% tamper detection.
5. **EVM Gas & Storage Cost Estimator (`crypto/gas_estimator.py`):**
   - EIP-2028 calldata gas, 32-byte storage slots, and USD economics.
6. **Recommendation Engine (`crypto/recommendation.py`):**
   - Rule-based mapping and risk scoring formula: `risk = algorithm_weight * exposure * signature_lifetime * confidence`.
7. **Canonical Report Signer (`crypto/report_signer.py`):**
   - Deterministic JSON canonicalization (RFC 8785), SHA-256 and Keccak-256 (`bytes32` for EVM) computation, and ML-DSA report digital signing.
8. **MCP Tool Suite (`mcp_crypto/crypto_tools.py`):**
   - Ready-to-serve MCP tools with strict schemas.
9. **Interactive CLI & Test Suite (`cli.py`, `tests/`):**
   - 42 passing unit tests in `pytest`.

---

## 2. Handoff for Member 2 (AI and Agents Lead)

### Using the Decision & Recommendation Engine in Agents:
```python
from crypto.recommendation import get_recommendation_for_use_case, calculate_quantum_risk

# 1. Compute quantum risk score for scanner findings:
risk_info = calculate_quantum_risk(
    algorithm_name="secp256k1",
    exposure_factor=1.0,
    signature_lifetime_years=5.0,
    confidence=0.98
)
# Returns: {'algorithm': 'secp256k1', 'risk_index': 93.1, 'severity': 'CRITICAL', 'migration_urgency': 'Immediate Migration Required'}

# 2. Get architectural PQC recommendation:
recommendation = get_recommendation_for_use_case("gas_constrained_evm")
# Returns: PQCRecommendation object (Falcon-512 with rationale and trade-offs)
```

---

## 3. Handoff for Member 3 (Backend & MCP Engineer)

### Serving Crypto Tools in MCP Server:
Member 3 can directly import the tool functions in `mcp_crypto/crypto_tools.py`:
```python
from mcp_crypto.crypto_tools import (
    tool_crypto_list_algorithms,
    tool_crypto_generate_keypair,
    tool_crypto_sign_message,
    tool_crypto_verify_signature,
    tool_crypto_run_tamper_matrix,
    tool_crypto_run_benchmark,
    tool_crypto_estimate_gas_costs,
    tool_crypto_sign_report,
    tool_crypto_get_recommendation,
)
```

### Report Generation & Canonical Hashing for REST API:
```python
from crypto.report_signer import PQCReportSigner, compute_report_hashes

# Generate hashes for on-chain anchoring
sha256_hash, keccak256_bytes32 = compute_report_hashes(assessment_report_dict)

# Sign report with ML-DSA
report_signer = PQCReportSigner(variant="ML-DSA-44")
signed_report = report_signer.sign_report(assessment_report_dict)
```

---

## 4. Handoff for Member 4 (Blockchain & Scanner Engineer)

### Passing the Canonical Hash to Smart Contract (`ReportRegistry.sol`):
The `keccak256_hash` returned by `compute_report_hashes()` is formatted as `0x...` (32 bytes), which maps directly to the Solidity `bytes32` parameter of `anchor(bytes32 reportHash)`:
```python
from crypto.report_signer import compute_report_hashes

sha256_hex, keccak256_hex = compute_report_hashes(canonical_report_dict)

# Pass keccak256_hex directly to web3.py / ethers:
# tx = reportRegistryContract.functions.anchor(keccak256_hex).transact({'from': account})
```

---

## 5. Handoff for Member 5 (Frontend, Voice & Demo Lead)

### Rendering Benchmark & Verification Charts:
Pre-computed schema files are ready in `docs/`:
- `docs/benchmark_results.json`: Formatted for Recharts bar & scatter charts (Signature sizes, Keygen/Sign/Verify times, EVM Gas overheads).
- `docs/verification_matrix.json`: Formatted for the Tamper Resistance matrix table.

### Live Terminal Demo Commands:
```bash
# Run full suite
python cli.py --all

# Run statistical benchmark with 100 iterations
python cli.py --benchmark

# Run 4-scenario tamper matrix
python cli.py --tamper-matrix

# Run hybrid ECDSA + ML-DSA dual signing demo
python cli.py --hybrid-demo

# Sign sample assessment report with ML-DSA
python cli.py --sign-report
```

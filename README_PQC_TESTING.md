# Q-Chain: Post-Quantum Cryptography (PQC) Signature Testing Module

**Assigned Ownership:** Team Member 2  
**Component:** Post-Quantum Cryptography Signature Testing & Benchmarking Module  
**Standardized Reference:** NIST FIPS 204 (Module-Lattice-Based Digital Signature Algorithm - ML-DSA)  
**Classical Baseline:** ECDSA secp256k1 (SEC 2 / ANSI X9.62)

---

## 1. Executive Summary & Purpose

Modern blockchain applications (including Bitcoin, Ethereum, and EVM-compatible networks) authorize transactions using classical elliptic-curve signatures—predominantly **ECDSA over `secp256k1`**. A sufficiently capable quantum computer executing Shor's polynomial-time algorithm would compute discrete logarithms, forging arbitrary user signatures and invalidating transaction integrity.

This module provides **Q-Chain's core PQC signature testing, tamper verification, and performance evaluation engine**. It demonstrates:
1. **NIST FIPS 204 ML-DSA implementation** across security categories:
   - **ML-DSA-44** (Dilithium2, NIST Category 2, equivalent to SHA-256 / AES-128)
   - **ML-DSA-65** (Dilithium3, NIST Category 3, equivalent to AES-192)
   - **ML-DSA-87** (Dilithium5, NIST Category 5, equivalent to AES-256)
2. **Side-by-side comparative evaluation** against the classical **ECDSA secp256k1** baseline.
3. **Automated 4-scenario cryptographic tamper matrix** proving tamper resistance.
4. **Live hardware performance benchmarking** with non-fabricated microsecond timings and EVM calldata/gas impact modelling.
5. **Clean REST API integration** via FastAPI APIRouter ready to be mounted into Member 3's backend.

---

## 2. Cryptographic Security & Honest Disclaimer (Rule 7)

> **Important Cryptanalytic Scope Statement:**  
> While **ML-DSA** is mathematically engineered around the hardness of the **Module Learning With Errors (M-LWE)** and **Module Short Integer Solution (M-SIS)** lattice problems—which resist known quantum polynomial-time attacks like Shor's algorithm—**passing functional signature tests does not imply absolute post-quantum security**. Real-world security remains governed by:
> - Constant-time implementation security to prevent side-channel timing and power leakage.
> - Fault-injection resistance during polynomial sampling and rejection rounds.
> - Ongoing advancements in lattice reduction algorithms (e.g., BKZ 2.0 with quantum sieving).
>
> In addition, migrating off-chain digital signatures does not automatically make existing on-chain smart contracts quantum-safe without chain protocol-level hard forks or signature aggregation precompiles.

---

## 3. Architecture & File Structure

This module is self-contained within `backend/pqc_testing/` so it does not conflict with other team members' code:

```
d:/Codechunkzz/
├── backend/
│   └── pqc_testing/
│       ├── __init__.py           # Unified exports for the module
│       ├── base.py               # Abstract base classes, typed models, and algorithm catalog
│       ├── mldsa_signer.py       # FIPS 204 ML-DSA (44, 65, 87) signer implementation
│       ├── ecdsa_signer.py       # Classical ECDSA secp256k1 baseline signer
│       ├── tamper_tester.py      # Automated 4-scenario adversarial tamper test suite
│       ├── benchmarker.py        # High-precision timing & gas impact benchmarker
│       ├── router.py             # FastAPI REST endpoints (/api/pqc/*)
│       └── cli.py                # Standalone interactive CLI test runner
├── tests/
│   └── test_pqc_testing.py       # 13 automated unit & integration tests
├── pqc_signature_tester.py       # Convenient root execution script
└── README_PQC_TESTING.md         # This specification and guide
```

---

## 4. Cryptographic Key & Signature Size Comparisons

Real byte sizes measured directly on hardware:

| Algorithm | Family | NIST Category | Public Key Size | Private Key Size | Signature Size | Combined Crypto Footprint | Overhead vs ECDSA |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **ECDSA (secp256k1)** | Classical ECC | 1 (Classical) | 65 bytes | 32 bytes | 64 bytes | **129 bytes** | **1.0x (Baseline)** |
| **ML-DSA-44** | PQC Lattice | 2 | 1,312 bytes | 2,528 bytes | 2,420 bytes | **3,732 bytes** | **28.9x** |
| **ML-DSA-65** | PQC Lattice | 3 | 1,952 bytes | 4,000 bytes | 3,293 bytes | **5,245 bytes** | **40.7x** |
| **ML-DSA-87** | PQC Lattice | 5 | 2,592 bytes | 4,864 bytes | 4,595 bytes | **7,187 bytes** | **55.7x** |

### EVM On-Chain Footprint Implications
On EVM chains (Ethereum), non-zero calldata costs approximately **16 gas per byte**:
- **ECDSA (secp256k1):** $129 \times 16 \approx \mathbf{2,064\text{ gas}}$
- **ML-DSA-44:** $3,732 \times 16 \approx \mathbf{59,712\text{ gas}}$
- **ML-DSA-65:** $5,245 \times 16 \approx \mathbf{83,920\text{ gas}}$
- **ML-DSA-87:** $7,187 \times 16 \approx \mathbf{114,992\text{ gas}}$

*Migration Insight:* While ML-DSA signatures are computationally fast, their transmission and on-chain storage require roughly $29\times$ to $56\times$ higher calldata payload space.

---

## 5. Tamper Testing Matrix

The module executes four automated adversarial test scenarios to prove signature authenticity and tamper-detection:

| Scenario | Attack Description | Expected Outcome | Actual Outcome | Status |
| :--- | :--- | :---: | :---: | :---: |
| **1. Authentic** | Unmodified message and valid signature | `True` (Valid) | `True` | **PASS** |
| **2. Modified Message** | 1 bit flipped in payload (simulating balance/recipient tampering) | `False` (Reject) | `False` | **PASS** |
| **3. Corrupted Signature** | 1 bit flipped midway inside signature body | `False` (Reject) | `False` | **PASS** |
| **4. Mismatched Public Key** | Signature validated against independent attacker key | `False` (Reject) | `False` | **PASS** |

**Tamper Detection Rate:** **100.0%** (all tampering attempts intercepted).

---

## 6. How to Run the Module

### Prerequisites
Installed via pip:
```bash
pip install dilithium-py cryptography fastapi uvicorn httpx pytest
```

### Running the Standalone CLI Runner
Test default ML-DSA-44:
```bash
python pqc_signature_tester.py
```

Test all algorithms (ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87) with 5 benchmark trials:
```bash
python pqc_signature_tester.py --algorithm all --trials 5
```

Export results to JSON:
```bash
python pqc_signature_tester.py --algorithm ML-DSA-44 --trials 10 --export-json pqc_report.json
```

### Running Unit & Integration Tests
```bash
python -m pytest tests/test_pqc_testing.py -v
```

---

## 7. REST API Endpoints (For Member 3 & Member 5 Integration)

The module exposes an APIRouter prefixed at `/api/pqc`:

### 1. `GET /api/pqc/algorithms`
Lists all supported algorithms with metadata, NIST security categories, and descriptions.

### 2. `POST /api/pqc/keygen`
Generates fresh keypairs.
```json
// Request
{
  "algorithm": "ML-DSA-44",
  "include_private_key": true
}
```

### 3. `POST /api/pqc/sign`
Signs an arbitrary payload.
```json
// Request
{
  "algorithm": "ML-DSA-44",
  "private_key_hex": "<hex_encoded_private_key>",
  "message": "Transfer 10 Q-TOKEN to 0x123..."
}
```

### 4. `POST /api/pqc/verify`
Verifies signature validity against message and public key.
```json
// Request
{
  "algorithm": "ML-DSA-44",
  "public_key_hex": "<hex_encoded_public_key>",
  "signature_hex": "<hex_encoded_signature>",
  "message": "Transfer 10 Q-TOKEN to 0x123..."
}
```

### 5. `POST /api/pqc/tamper-test`
Executes the full 4-scenario tamper verification suite and returns the pass/fail matrix.
```json
// Request
{
  "algorithm": "ML-DSA-44"
}
```

### 6. `POST /api/pqc/benchmark`
Runs real hardware timing trials and returns keygen, sign, verify stats, and gas estimates.
```json
// Request
{
  "algorithm": "ML-DSA-44",
  "trials": 10
}
```

### Mount into FastAPI App (For Member 3)
In Member 3's FastAPI entry point:
```python
from fastapi import FastAPI
from backend.pqc_testing import pqc_router

app = FastAPI(title="Q-Chain API")
app.include_router(pqc_router)
```

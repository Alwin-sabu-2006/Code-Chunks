# Q-Chain: Cryptography & Post-Quantum Cryptography (PQC) Engine

**Role:** Member 1 — Crypto & PQC Lead  
**Scope:** Sections 4.2, 4.3, 7.2, 7.3, 15 (Phase 0 through Phase 5)  
**Track:** Security (Blockchain & Cryptography)

---

## 📌 Deliverables Summary

| Component | Status | Description |
| :--- | :---: | :--- |
| **Docker liboqs Environment** | ✅ Complete | Containerized Linux environment with `liboqs` C library and Python bindings (`docker/Dockerfile.crypto`) |
| **PQC & Classical Signers** | ✅ Complete | ECDSA (secp256k1), ML-DSA (44/65/87), SLH-DSA (128f/128s/256f), Falcon (512/1024), Hybrid Schemes |
| **Statistical Benchmark Harness** | ✅ Complete | 100+ iteration nanosecond timing harness measuring keygen, sign, verify, mean & std dev |
| **Tamper Resistance Matrix** | ✅ Complete | 4-scenario adversarial suite (valid, flipped msg bit, flipped sig bit, wrong key) with **100% detection rate** |
| **EVM Gas & Storage Estimator** | ✅ Complete | On-chain calldata gas (EIP-2028), 32-byte storage slots, and USD economics |
| **PQC Recommendation Engine** | ✅ Complete | Use-case mapping and quantum risk scoring formula |
| **Report Canonical Hashing & Signer** | ✅ Complete | RFC 8785 canonical JSON, SHA-256 / Keccak-256 (`bytes32`) hash computation & ML-DSA signing |
| **MCP Crypto Tools** | ✅ Complete | Pre-built tools for Member 3 (`mcp_crypto/crypto_tools.py`) |
| **Test Suite** | ✅ 42/42 Passed | 100% passing tests in `pytest` |
| **Pitch & Technical Docs** | ✅ Complete | `docs/PQC_ALGORITHM_EXPLANATIONS.md`, `docs/BENCHMARK_REPORT.md`, `docs/CRYPTO_LEAD_HANDOFF.md` |

---

## 🚀 Quickstart & Usage

### 1. Run Complete Test Suite with Pytest
```bash
python -m pytest -v
```

### 2. Run Interactive CLI
```bash
# Run complete verification and benchmark suite
python cli.py --all

# Run statistical benchmarks (100 iterations per algorithm)
python cli.py --benchmark

# Run 4-scenario tamper verification suite
python cli.py --tamper-matrix

# Run EVM gas overhead estimation
python cli.py --gas-estimate

# Run Hybrid ECDSA + ML-DSA dual signature demonstration
python cli.py --hybrid-demo

# Sign sample assessment report with ML-DSA and verify hash
python cli.py --sign-report
```

### 3. Docker Deployment
```bash
docker build -t qchain-crypto -f docker/Dockerfile.crypto .
docker run --rm qchain-crypto --all
```

---

## 🏛️ Architecture & Algorithm Support

```
[ CryptoRegistry ]
  ├── Classical:
  │     └── ECDSA_secp256k1 (SECG SEC2 / FIPS 186-5)
  ├── Lattice-Based (NIST FIPS 204):
  │     ├── ML-DSA-44 (Dilithium2, NIST Level 2)
  │     ├── ML-DSA-65 (Dilithium3, NIST Level 3)
  │     └── ML-DSA-87 (Dilithium5, NIST Level 5)
  ├── Hash-Based (NIST FIPS 205):
  │     ├── SLH-DSA-SHAKE-128f (SPHINCS+ 128 Fast, NIST Level 1)
  │     ├── SLH-DSA-SHAKE-128s (SPHINCS+ 128 Small, NIST Level 1)
  │     └── SLH-DSA-SHAKE-256f (SPHINCS+ 256 Fast, NIST Level 5)
  ├── NTRU Lattice (Draft FN-DSA):
  │     ├── Falcon-512 (NIST Level 1, 666-byte signature)
  │     └── Falcon-1024 (NIST Level 5)
  └── Hybrid Dual Scheme:
        ├── Hybrid_ECDSA_ML-DSA-44 (Dual sign & verify)
        └── Hybrid_ECDSA_ML-DSA-65
```

---

## ⚖️ Honest Scope Statement

> *"Q-Chain assesses and verifies migration readiness. It does not claim that off-chain PQC signatures make existing on-chain transaction authorization quantum-safe, and the anchoring transaction itself still relies on the host chain's classical signatures."*

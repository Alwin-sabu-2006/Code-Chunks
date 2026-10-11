# Q-Chain: Post-Quantum Cryptography Technical Reference & Pitch Guide

> **Prepared by:** Member 1 (Crypto & PQC Lead)  
> **Track:** Security (Blockchain & Cryptography)  
> **Date:** Hackathon 2026

---

## 1. The Core Threat: Shor's Algorithm vs Classical Cryptography

### Why Classical Blockchain Signatures Are Vulnerable
- **ECDSA (secp256k1)** relies on the **Discrete Logarithm Problem (DLP)** over elliptic curves.
- In classical computation, computing discrete logs takes sub-exponential time: $\mathcal{O}(\sqrt{p})$.
- A sufficiently capable fault-tolerant quantum computer running **Shor's Algorithm** solves DLP in **polynomial time $\mathcal{O}((\log N)^3)$**.
- **Impact:** Any public key exposed on-chain (from past transactions, contract creation, or ecrecover verification) allows an attacker with a quantum computer to reconstruct the private key and forge transactions with zero detection.

---

## 2. NIST Post-Quantum Cryptography Standards (FIPS 204 & 205)

### A. ML-DSA (Module-Lattice Digital Signature Algorithm) — NIST FIPS 204
- **Origin:** Based on CRYSTALS-Dilithium (NIST Primary Standard, finalized August 2024).
- **Underlying Math:** Hardness of the Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS) problems in algebraic number fields.
- **Why it is the General-Purpose Standard:**
  - Fast, constant-time modular arithmetic without complex floating-point hardware.
  - Sub-millisecond signing and verification times.
  - Deterministic Fiat-Shamir with Abort signature structure.
- **NIST Parameter Sets:**
  - **ML-DSA-44 (Dilithium2):** NIST Security Level 2 (128-bit quantum security). Public Key: **1,312 B**, Signature: **2,420 B**.
  - **ML-DSA-65 (Dilithium3):** NIST Security Level 3 (192-bit quantum security). Public Key: **1,952 B**, Signature: **3,309 B**.
  - **ML-DSA-87 (Dilithium5):** NIST Security Level 5 (256-bit quantum security). Public Key: **2,592 B**, Signature: **4,627 B**.

---

### B. SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) — NIST FIPS 205
- **Origin:** Based on SPHINCS+ (NIST Hash-Based Standard, finalized August 2024).
- **Underlying Math:** Relies **exclusively** on the collision and pre-image resistance of cryptographic hash functions (SHAKE-256 / SHA3).
- **Why it is the "Safety Net":**
  - **Zero Lattice Assumptions:** If an unexpected mathematical breakthrough weakens lattice problems, SLH-DSA remains 100% secure.
  - Highly conservative security proof for ultra-high-value cold storage and sovereign DAO treasuries.
- **Trade-off:**
  - Larger signature footprint (17,088 bytes for 128f, 49,856 bytes for 256f).
  - High EVM calldata gas cost if used on-chain.

---

### C. Falcon / FN-DSA (Fast-Fourier Lattice-based Signatures over NTRU)
- **Origin:** NIST Round 3 selected standard (under final standardization as FN-DSA).
- **Underlying Math:** Short Integer Solution over NTRU lattices, sampled using Fast Fourier transform (FFT) over the complex plane.
- **Why it is Ideal for Blockchains:**
  - **Smallest Combined Footprint:** Signature is only **666 bytes** (Falcon-512) vs 2,420 bytes for ML-DSA-44.
  - EVM calldata gas is ~10,656 gas (**72% cheaper than ML-DSA**).
- **Trade-off:**
  - Requires constant-time floating-point arithmetic or emulation during signing to prevent timing side-channel attacks.

---

### D. Hybrid Dual-Signing Schemes (ECDSA + ML-DSA)
- **Concept:** Concatenates classical ECDSA (secp256k1) with post-quantum ML-DSA.
- **Verification Rule:** The verification function only returns `True` if **BOTH** signatures are mathematically valid against the message payload.
- **Migration Value:**
  1. Backwards compatible with legacy Ethereum consensus and layer-1 node verification.
  2. Forwards compatible against future cryptanalytic advances.
  3. Complies with CNSA 2.0 quantum migration guidelines.

---

## 3. Pitch Slide Deck: Algorithm Comparison Cheat Sheet for Judges

| Algorithm | Type | NIST Level | Public Key | Signature | EVM Calldata Gas | Primary Use Case |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **ECDSA (secp256k1)** | Classical Elliptic Curve | 0 *(Broken)* | 33 B | 64 B | 1,024 gas | *Current Ethereum Baseline* |
| **Falcon-512** | NTRU Lattice (FN-DSA) | 1 (128-bit) | 897 B | 666 B | 10,656 gas | **On-chain smart contracts & rollup txs** |
| **ML-DSA-44** | Module-LWE (FIPS 204) | 2 (128-bit) | 1,312 B | 2,420 B | 38,720 gas | **General wallets, dApps & account abstraction** |
| **SLH-DSA-128f** | Stateless Hash (FIPS 205)| 1 (128-bit) | 32 B | 17,088 B | 273,408 gas | **Cold storage & long-term sovereign governance** |
| **Hybrid Dual** | ECDSA + ML-DSA-44 | 2 (128-bit) | 1,345 B | 2,484 B | 39,744 gas | **Immediate safe production migration** |

---

## 4. Honest Scope Statement (Must be in Every Pitch)

> **"Q-Chain assesses and verifies migration readiness. It does not claim that off-chain PQC signatures make existing on-chain transaction authorization quantum-safe, and the anchoring transaction itself still relies on the host chain's classical signatures."**

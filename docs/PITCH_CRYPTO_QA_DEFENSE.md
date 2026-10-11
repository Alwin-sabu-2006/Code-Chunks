# Q-Chain: Cryptography Lead Pitch Defense & Judge Q&A Guide

> **Prepared for:** Member 1 (Crypto & PQC Lead)  
> **Purpose:** Defend the cryptographic architecture and answer judge questions during the hackathon pitch.

---

## 🎯 High-Probability Judge Questions & Prepared Model Answers

### Q1: "Why can't we just use larger RSA or larger Elliptic Curves?"
**Answer:**  
> "Classical public key cryptography relies on the Discrete Logarithm Problem or Integer Factorization. Shor's algorithm solves both in **polynomial time** $\mathcal{O}((\log N)^3)$. Increasing key sizes only gives a linear or polynomial slowdown to a quantum attacker while causing exponential penalties for classical verifiers. Post-Quantum Cryptography replaces these underlying mathematical groups with problems like **Shortest Vector Problem (SVP)** in high-dimensional lattices or **hash collision resistance**, which have no known polynomial-time quantum solutions."

---

### Q2: "Why did you benchmark both ML-DSA (FIPS 204) and Falcon (FN-DSA)?"
**Answer:**  
> "They represent two distinct architectural trade-offs within lattice cryptography:
> - **ML-DSA-44 (FIPS 204):** NIST's primary standard based on Module-LWE. It uses constant-time integer arithmetic with zero floating-point operations, making it extremely secure against timing side-channels and ideal for general-purpose wallet signing.
> - **Falcon-512 (FN-DSA):** Uses Fast-Fourier sampling over NTRU lattices. It produces the **smallest signature (666 bytes)** among all NIST candidates, saving **72% in EVM calldata gas** (~10,656 gas vs ~38,720 gas for ML-DSA-44). In gas-constrained blockchain environments, Falcon is the most economical PQC algorithm."

---

### Q3: "What happens if lattice-based cryptography is broken in the future?"
**Answer:**  
> "That is why we included **SLH-DSA (FIPS 205 / SPHINCS+)** in our platform:
> - SLH-DSA is a **stateless hash-based signature scheme**. It makes **zero hardness assumptions about lattices**. Its security relies strictly on the pre-image and collision resistance of SHAKE-256 / SHA-3.
> - Even if mathematical advances were to solve Module-LWE, SLH-DSA remains unconditionally secure against lattice cryptanalysis. We recommend SLH-DSA for ultra-long-term DAO treasury reserves and sovereign storage."

---

### Q4: "How does your Hybrid (ECDSA + ML-DSA) signature protect blockchain migrations?"
**Answer:**  
> "Migrating live blockchains is high-risk. A **hybrid dual-signature scheme** concatenates a classical ECDSA secp256k1 signature with a quantum-safe ML-DSA signature:
> 1. Legacy nodes and existing EVM smart contracts verify the 64-byte ECDSA signature using `ecrecover`.
> 2. Quantum-aware nodes verify the ML-DSA signature.
> 3. Verification succeeds **only if both signatures are valid**. An attacker must break both classical elliptic curves AND 128-bit lattice cryptography simultaneously."

---

### Q5: "What is the exact scope of Q-Chain regarding on-chain quantum safety?"
*(The Honest Scope Statement)*  
**Answer:**  
> "Q-Chain assesses and verifies **migration readiness**. We scan codebases to detect vulnerable classical cryptographic patterns, run statistical benchmarks, test tamper resistance, and calculate gas overheads. We do not claim that off-chain signatures magically make existing Layer-1 consensus quantum-safe, as on-chain verification will eventually require native PQC precompiles or account abstraction (ERC-4337)."

---

## ⚡ 60-Second Cryptography Pitch Elevator Pitch

> *"Most of today's $2 trillion blockchain ecosystem secures transactions using classical ECDSA secp256k1. Shor's algorithm on a quantum computer will forge these signatures in polynomial time.  
> Q-Chain solves the migration barrier. Our PQC engine benchmarks NIST FIPS 204 ML-DSA, FIPS 205 SLH-DSA, and Falcon against classical baselines, measuring nanosecond latency, tamper resistance, and EVM gas costs. We prove that Falcon-512 reduces calldata gas by 72% over standard lattice schemes, while our hybrid ECDSA + ML-DSA dual scheme allows zero-downtime migration starting today."*

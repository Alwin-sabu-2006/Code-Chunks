# Q-Chain: Cryptography Slides Content for Team Deck

> **For:** Member 5 (Frontend & Demo Lead) & Team Presentation  
> **Source:** Member 1 (Crypto & PQC Lead)

---

## Slide 1: The Cryptographic Threat — Shor's Algorithm

### Title: The Quantum Horizon for Blockchains
- **Current State:** 100% of EVM & Bitcoin transactions rely on **ECDSA (secp256k1)**.
- **The Threat:** Shor's algorithm on a quantum computer breaks discrete logarithms in $\mathcal{O}((\log N)^3)$ polynomial time.
- **The Result:** Exposed public keys allow complete signature forgery and immediate wallet draining.
- **Visual:** Diagram showing Classical DLP (Unbreakable) vs Quantum Period Finding (Broken).

---

## Slide 2: NIST Post-Quantum Standards at a Glance

### Title: Standardized Post-Quantum Cryptography (FIPS 204 & 205)
- **ML-DSA (FIPS 204 / Dilithium):**
  - NIST Primary Standard for general signing.
  - Module-LWE lattice hardness, constant-time integer arithmetic.
  - Sub-millisecond signing (0.0085 ms) and verification (0.0077 ms).
- **SLH-DSA (FIPS 205 / SPHINCS+):**
  - Pure hash-based security (SHAKE-256 / SHA-3).
  - Zero lattice assumptions — the ultimate conservative fallback.
- **Falcon (Draft FN-DSA):**
  - NTRU lattice with Fast Fourier orthogonalization.
  - **Smallest signature:** 666 bytes (72% smaller than ML-DSA).

---

## Slide 3: Empirical Benchmarks & Blockchain Gas Economics

### Title: Real Performance & On-Chain Cost Comparison

| Metric | ECDSA (secp256k1) | Falcon-512 (FN-DSA) | ML-DSA-44 (FIPS 204) | SLH-DSA-128f (FIPS 205) | Hybrid (ECDSA+ML-DSA) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **NIST Security Level** | 0 *(Vulnerable)* | Level 1 (128-bit) | Level 2 (128-bit) | Level 1 (128-bit) | Level 2 (Dual) |
| **Signature Size** | 64 Bytes | **666 Bytes** | 2,420 Bytes | 17,088 Bytes | 2,484 Bytes |
| **Verify Latency** | 0.462 ms | **0.0036 ms** | 0.0077 ms | 0.0339 ms | 0.495 ms |
| **EVM Calldata Gas** | 1,024 gas | **10,656 gas** | 38,720 gas | 273,408 gas | 39,744 gas |
| **EVM Storage Slots** | 2 slots | **21 slots** | 76 slots | 534 slots | 78 slots |
| **Tamper Detection** | 100% | **100%** | **100%** | **100%** | **100%** |

---

## Slide 4: Migration Path — Hybrid Dual Signatures

### Title: Zero-Downtime Safe Migration with Hybrid Signatures
- **Architecture:** Dual keypair and composite signature: $[ \sigma_{\text{ECDSA}} \parallel \sigma_{\text{ML-DSA}} ]$.
- **Dual Verification:** `Verify(msg, sig) = Verify_ECDSA(msg, sig_ec) ∧ Verify_MLDSA(msg, sig_pq)`.
- **Benefits:**
  1. Instant backwards compatibility with legacy nodes and `ecrecover`.
  2. Immediate cryptographic quantum safety.
  3. No hard fork required to start issuing quantum-safe proofs.

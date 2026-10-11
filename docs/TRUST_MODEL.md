# Q-Chain Blockchain Trust Model (Judge's Guide)

## Core Honest Scope Statement
**Q-Chain assesses and verifies migration readiness.** It does **not** claim that off-chain PQC signatures make existing on-chain transaction authorization quantum-safe, and the anchoring transaction itself still relies on the host chain's classical signatures.

## What Anchoring DOES Prove
1. **Report Integrity (Tamper-Evidence):** By anchoring the SHA-256 or Keccak-256 digest of the canonical JSON report to an EVM smart contract, we establish a cryptographically secure, immutable anchor. Any modification to the report (even a single flipped bit, like changing "CRITICAL" to "LOW") results in a completely different hash that the blockchain will reject as `NOT_FOUND`.
2. **Timestamping & Non-Repudiation:** The block timestamp provides an undeniable mathematical proof that a specific security assessment took place at a specific point in time, verified by the decentralized network.
3. **Auditable Trail:** Teams migrating to PQC can point to their on-chain anchors as proof of compliance or progress across a timeline without revealing sensitive proprietary code.

## What Anchoring DOES NOT Prove (and Limitations)
1. **Execution Authenticity:** The anchor proves the *report* was submitted, but it does not run the scanner on-chain. Judges should know that a malicious user could theoretically submit a fake report hash. (A future integration could involve zk-SNARKs to prove correct execution of the scanner).
2. **Quantum-Safe Authorization:** The transactions used to anchor the reports (`msg.sender` signatures) are signed using classical ECDSA secp256k1 curves on Ethereum/Sepolia. Therefore, if a cryptographically relevant quantum computer (CRQC) breaks the host chain, the anchor's provenance could be forged. Long-term trust relies on the host chain migrating its own consensus/authorization to quantum-resistant schemes.
3. **Indirect Vulnerabilities:** The scanner operates via static pattern matching. It does not perform dynamic data-flow analysis and might miss highly obfuscated or indirect usage of classical cryptographic libraries.

## The Recommendation Strategy
- Constrained gas/storage -> Favors **Falcon-512**.
- Conservative long-term security -> Favors **SLH-DSA** (stateless hash-based).
- Balanced general use off-chain -> Favors **ML-DSA-44 or ML-DSA-65**.

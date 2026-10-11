# Sample 3: Multi-Signature Vault

### Documented Planted Vulnerabilities
1. `contracts/MultiSig.sol:28` — `ecrecover` in threshold loop (Solidity secp256k1).
2. `src/client.ts:9` — `ed25519.sign` call (Noble Ed25519 discrete-log curve).

Expected detection score: **2 of 2** (100%).

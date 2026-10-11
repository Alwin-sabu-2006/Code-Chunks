# VulnChain ground truth (for scoring Q-Chain's scanner)

Search the code for `FINDING` and `DECOY` comments. A good scan reports all five
findings and none of the decoys.

## Should be flagged (quantum-vulnerable)

| # | File | Pattern | Why it is vulnerable | PQC direction (to evaluate) |
|---|------|---------|----------------------|-----------------------------|
| 1 | wallet.py | `ec.SECP256K1()`, `ec.generate_private_key` | Elliptic-curve keys; Shor recovers the private key | ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Falcon |
| 2 | wallet.py | `ec.ECDSA(hashes.SHA256())` sign and verify | ECDSA signatures are forgeable once the key is recovered | ML-DSA, SLH-DSA, Falcon |
| 3 | ledger.py | `sender_pub` stored in every `Transaction` | Public key exposed on-chain at spend time | Same signature migration; avoid exposing keys longer than needed |
| 4 | node_identity.py | `rsa.generate_private_key(... 2048)`, RSA `PKCS1v15` sign/verify | RSA falls to Shor | ML-DSA, SLH-DSA |
| 5 | node_identity.py | `ec.ECDH()` with P-256 | Key agreement breaks to Shor; recorded handshakes can be decrypted later | ML-KEM (FIPS 203), ideally hybrid |

## Should NOT be flagged (decoys, test for false positives)

| File | Pattern | Why it is not a quantum finding |
|------|---------|---------------------------------|
| wallet.py | `hashlib.sha256` in `address_of` | Hashing only loses a little strength to Grover |
| ledger.py | `hashlib.sha256` in `hash_block` | Same |

## Scoring

- Recall = findings reported / 5
- Precision = correct findings reported / all findings reported
- Decoys flagged = false positives (target: 0)

## Test checks for the verification agent

1. Valid chain verifies (`GET /verify` returns `valid: true`).
2. Edit an amount: verification fails with a hash mismatch.
3. Edit an amount and recompute the block hash: verification fails on the signature.
4. Sign with the wrong key: the transaction is rejected.
5. Record ECDSA baseline from `python demo.py` (key size, signature size, sign and verify time) to compare against each PQC candidate.

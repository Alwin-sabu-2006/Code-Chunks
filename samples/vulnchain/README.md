# VulnChain

A toy blockchain app that is deliberately quantum-vulnerable. It exists as the
target that Q-Chain scans, tests and verifies. Not for production use.

## Run it

```
pip install -r requirements.txt
python test_vulnchain.py     # 6 tests: signatures, tamper detection, handshake
python demo.py               # end-to-end demo + ECDSA baseline numbers
python app.py                # HTTP API on http://127.0.0.1:8000
```

## Try the API

```
curl -X POST localhost:8000/wallet            # run twice: wallet 1 and 2
curl -X POST localhost:8000/tx -d '{"wallet_id":"1","recipient":"<address of wallet 2>","amount":25}'
curl -X POST localhost:8000/mine
curl localhost:8000/verify                    # valid: true
curl -X POST localhost:8000/tamper -d '{"block":1,"tx":0,"amount":99}'
curl localhost:8000/verify                    # valid: false
```

## What is in it

| File | Role | Quantum-relevant content |
|------|------|--------------------------|
| wallet.py | Keys, signing, verifying | ECDSA secp256k1 |
| ledger.py | Transactions, blocks, chain verification | Public key in every transaction |
| node_identity.py | Node identity and peer handshake | RSA-2048, ECDH P-256 |
| app.py | Demo HTTP API | Calls the above |
| demo.py | Scenario and ECDSA baseline | Benchmark reference |
| test_vulnchain.py | Unit tests | Tamper and signature checks |
| expected_findings.md | Ground truth | 5 findings, 2 decoys |

## Using it with Q-Chain

1. Point the cryptographic analysis agent at this folder.
2. Compare its report with `expected_findings.md` (recall, precision, decoys).
3. Let the PQC testing agent sign and verify the same payloads with candidate algorithms and compare size and speed with `python demo.py`.
4. Let the verification agent run the tamper checks, then anchor the report hash on-chain.

Crypto calls are kept in three files on purpose, so swapping `Wallet.sign`, `verify` and the node handshake is a small, testable migration.

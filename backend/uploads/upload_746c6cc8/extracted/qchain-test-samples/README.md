# Q-Chain scanner test pack

Run each file through New Scan on its own, then compare with `expected.json`.

| File | Language | Expected result |
|------|----------|-----------------|
| VulnVault.sol | Solidity | 3 findings, 2 decoys not flagged |
| wallet.js | JavaScript | 4 findings, 2 decoys not flagged |
| clean_control.py | Python | Clean, zero findings (analyzed, not skipped) |
| pqc_migrated.py | Python | Zero vulnerable findings, PQC noted as present |
| unsupported_sample.go | Go | 2 findings, or "could not analyze"; never "quantum-safe" |
| vulnchain (earlier zip) | Python | 5 findings, 2 decoys |

Pass criteria for the whole pack:
1. Recall: every listed finding is reported.
2. Precision: no decoy is flagged.
3. Fail-closed: unparseable or unsupported input never produces a "Quantum-Safe / PASS" result.
4. Coverage shown: the result states files scanned, language detected and lines scanned.

These samples are static test inputs. The Solidity and Go files are not compiled here.

# Sample App 2: Decentralized Voting dApp

## Overview
A voting dApp featuring an on-chain Solidity ballot verification contract (`BallotVerifier.sol`) and an off-chain Python voter client (`vote_client.py`).

## Planted Vulnerable Patterns (7 Planted)
1. **BallotVerifier.sol: Line 22**: EIP-191 prefix string concatenation (`QC-SOL-003`, HIGH)
2. **BallotVerifier.sol: Line 38**: Native EVM `ecrecover(...)` precompile (`QC-SOL-001`, CRITICAL)
3. **vote_client.py: Line 13**: `Account.from_key(...)` (`QC-PY-001`, CRITICAL)
4. **vote_client.py: Line 16**: `Account.create()` (`QC-PY-001`, CRITICAL)
5. **vote_client.py: Line 24**: `encode_defunct(...)` hash-and-sign framing (`QC-PY-002`, CRITICAL)
6. **vote_client.py: Line 27**: `account.sign_message(...)` (`QC-PY-002`, CRITICAL)
7. **vote_client.py: Line 44**: `Account.recover_message(...)` (`QC-PY-003`, CRITICAL)

## Migration Target
- Replace off-chain ballot signatures with NIST ML-DSA or Falcon signatures.
- Anchor voter merkle roots with PQC verification off-chain or via zk-SNARK verifier.

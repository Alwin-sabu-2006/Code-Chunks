# Sample App 3: Multi-Signature Treasury Vault

## Overview
A threshold multi-signature contract (`MultiSigWallet.sol`) and TypeScript signer client (`multisig_signer.ts`) requiring M valid signatures before transactions execute.

## Planted Vulnerable Patterns (6 Planted)
1. **MultiSigWallet.sol: Line 32**: EIP-191 personal sign hash prefix (`QC-SOL-003`, HIGH)
2. **MultiSigWallet.sol: Line 61**: Native EVM `ecrecover(...)` precompile loop (`QC-SOL-001`, CRITICAL)
3. **multisig_signer.ts: Line 20**: `web3.eth.accounts.create()` (`QC-WEB3-001`, CRITICAL)
4. **multisig_signer.ts: Line 28**: `web3.eth.accounts.sign(...)` (`QC-WEB3-002`, CRITICAL)
5. **multisig_signer.ts: Line 36**: `web3.eth.accounts.recover(...)` (`QC-WEB3-003`, CRITICAL)
6. **multisig_signer.ts: Line 45**: Hardcoded secp256k1 field constant (`QC-SEC-001`, HIGH)

## Migration Target
- Replace secp256k1 threshold signatures with stateful hash-based trees or post-quantum lattice signature aggregation.

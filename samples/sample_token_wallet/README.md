# Sample App 1: Quantum-Vulnerable Token Wallet

## Overview
A representative TypeScript Web3 wallet service performing key generation, personal message signing, EIP-712 typed data signing, and raw transaction creation.

## Planted Vulnerable Patterns (7 Planted)
1. **Line 19**: `new ethers.Wallet(privateKey)` - Classical secp256k1 key instantiation (`QC-ETH-001`, CRITICAL)
2. **Line 22**: `ethers.Wallet.createRandom()` - Classical secp256k1 key generation (`QC-ETH-001`, CRITICAL)
3. **Line 35**: `new ethers.SigningKey(...)` - Low-level elliptic curve point manipulation (`QC-ETH-005`, HIGH)
4. **Line 44**: `wallet.signMessage(...)` - secp256k1 message signing (`QC-ETH-002`, CRITICAL)
5. **Line 56**: `wallet.signTypedData(...)` - EIP-712 structured hash-and-sign (`QC-ETH-006`, CRITICAL)
6. **Line 63**: `wallet.signTransaction(...)` - Classical transaction authorization (`QC-ETH-003`, CRITICAL)
7. **Line 71**: `ethers.verifyMessage(...)` - Classical public key recovery and verification (`QC-ETH-004`, CRITICAL)

## Migration Target
- Replace off-chain message attestation with NIST FIPS 204 (ML-DSA-65) or Falcon-512.
- Integrate ERC-4337 smart accounts for post-quantum validation modules.

# Sample 1: ERC-20 Token Wallet

### Documented Planted Vulnerabilities
1. `contracts/TokenVault.sol:34` — `ecrecover` signature verification (Solidity secp256k1).
2. `src/wallet.ts:9` — `ethers.Wallet` initialization (JavaScript secp256k1).
3. `src/wallet.ts:14` — `wallet.signMessage` call (JavaScript ECDSA signing).
4. `scripts/deploy.py:11` — `Account.from_key` (Python eth_account key derivation).
5. `scripts/deploy.py:13` — `Account.sign_message` (Python eth_account message signing).

Expected detection score: **5 of 5** (100%).

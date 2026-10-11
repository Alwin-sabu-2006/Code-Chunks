# Sample 2: Decentralized Voting dApp

### Documented Planted Vulnerabilities
1. `contracts/Ballot.sol:25` — `ecrecover` call on vote digest (Solidity secp256k1).
2. `src/voter.js:10` — `web3.eth.accounts.sign` call (Web3.js classical key signing).

Expected detection score: **2 of 2** (100%).

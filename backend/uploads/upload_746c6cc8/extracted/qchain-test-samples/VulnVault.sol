// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// INTENTIONALLY QUANTUM-VULNERABLE demo contract (Q-Chain test sample).
/// Not audited, not compiled in CI, do not deploy.
contract VulnVault {
    // FINDING 3: secp256k1 group order used for signature-malleability checks
    uint256 private constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => uint256) public commitments;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // FINDING 1: ecrecover (ECDSA on secp256k1) authorizes withdrawals off-chain
    function withdrawWithSig(
        address owner,
        address payable to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(uint256(s) <= SECP256K1_N / 2, "malleable signature");
        bytes32 digest = keccak256(abi.encodePacked(owner, to, amount, nonce, address(this)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        address signer = ecrecover(ethHash, v, r, s);
        require(signer != address(0) && signer == owner, "bad signature");
        require(nonce == nonces[owner], "bad nonce");
        require(balances[owner] >= amount, "insufficient");
        nonces[owner] = nonce + 1;
        balances[owner] -= amount;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // FINDING 2: OpenZeppelin ECDSA.recover (same ECDSA assumption, library form)
    function isAuthorized(bytes32 hash, bytes calldata signature, address expected)
        external
        pure
        returns (bool)
    {
        return ECDSA.recover(hash, signature) == expected;
    }

    // DECOY (not quantum-vulnerable): hash-based commit and reveal
    function commit(bytes32 commitment) external {
        commitments[commitment] = block.number;
    }

    function reveal(bytes calldata secret) external view returns (bool) {
        bytes32 c = sha256(abi.encodePacked(secret));
        return commitments[c] != 0;
    }
}

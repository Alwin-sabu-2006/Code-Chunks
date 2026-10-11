// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Sample App 3: Multi-Signature Treasury Vault
 * Implements M-of-N threshold signatures over off-chain authorized transactions.
 */
contract MultiSigWallet {
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public requiredSignatures;
    uint256 public nonce;

    event ExecutionSuccess(bytes32 txHash);
    event ExecutionFailure(bytes32 txHash);

    constructor(address[] memory _owners, uint256 _required) {
        require(_owners.length >= _required && _required > 0, "Invalid owner config");
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0) && !isOwner[owner], "Duplicate/invalid owner");
            isOwner[owner] = true;
            owners.push(owner);
        }
        requiredSignatures = _required;
    }

    function getTransactionHash(
        address destination,
        uint256 value,
        bytes memory data,
        uint256 txNonce
    ) public pure returns (bytes32) {
        bytes32 dataHash = keccak256(abi.encodePacked(destination, value, data, txNonce));
        // Planted Pattern 1: EIP-191 hash-and-sign prefix
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash));
    }

    /**
     * Executes transaction upon verifying M distinct classical ECDSA signatures
     */
    function executeTransaction(
        address destination,
        uint256 value,
        bytes memory data,
        bytes[] memory signatures
    ) external returns (bool) {
        require(signatures.length >= requiredSignatures, "Not enough signatures");
        bytes32 txHash = getTransactionHash(destination, value, data, nonce);
        nonce++;

        address lastSigner = address(0);

        for (uint256 i = 0; i < signatures.length; i++) {
            bytes memory sig = signatures[i];
            require(sig.length == 65, "Invalid signature length");

            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(sig, 32))
                s := mload(add(sig, 64))
                v := byte(0, mload(add(sig, 96)))
            }

            // Planted Pattern 2: Classical EVM ecrecover precompile
            address signer = ecrecover(txHash, v, r, s);
            require(isOwner[signer], "Signature not from owner");
            require(signer > lastSigner, "Signers must be strictly increasing");
            lastSigner = signer;
        }

        (bool success, ) = destination.call{value: value}(data);
        if (success) {
            emit ExecutionSuccess(txHash);
        } else {
            emit ExecutionFailure(txHash);
        }
        return success;
    }
}

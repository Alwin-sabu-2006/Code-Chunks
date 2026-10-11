// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MultiSig
 * @notice Multi-signature wallet with off-chain classical threshold authorization
 */
contract MultiSig {
    address[] public owners;
    uint256 public requiredSignatures;

    mapping(bytes32 => bool) public executed;

    constructor(address[] memory _owners, uint256 _required) {
        owners = _owners;
        requiredSignatures = _required;
    }

    // VULNERABILITY #1: ecrecover loop verifying threshold of classical signatures
    function executeTransaction(
        bytes32 txHash,
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s
    ) external {
        require(!executed[txHash], "Already executed");
        require(v.length >= requiredSignatures, "Not enough signatures");

        uint256 validCount = 0;
        for (uint256 i = 0; i < v.length; i++) {
            address recovered = ecrecover(txHash, v[i], r[i], s[i]);
            if (isOwner(recovered)) {
                validCount++;
            }
        }
        require(validCount >= requiredSignatures, "Threshold not met");
        executed[txHash] = true;
    }

    function isOwner(address account) internal view returns (bool) {
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == account) return true;
        }
        return false;
    }
}

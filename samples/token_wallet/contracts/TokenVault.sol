// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TokenVault
 * @notice Vulnerable sample contract using classical secp256k1 ecrecover
 * Planted vulnerability: ecrecover is vulnerable to Shor's algorithm on quantum hardware.
 */
contract TokenVault {
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public executedTransfers;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // VULNERABILITY #1: Classical secp256k1 ecrecover signature verification
    function withdrawWithSignature(
        address owner,
        uint256 amount,
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(!executedTransfers[messageHash], "Transfer already executed");
        require(balances[owner] >= amount, "Insufficient balance");

        // Classical ECDSA recovery - quantum vulnerable
        address signer = ecrecover(messageHash, v, r, s);
        require(signer == owner, "Invalid signature");

        executedTransfers[messageHash] = true;
        balances[owner] -= amount;
        payable(owner).transfer(amount);

        emit Withdrawn(owner, amount);
    }
}

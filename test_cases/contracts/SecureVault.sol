// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Threat 3: Test Case 2 — Corrected withdrawal ordering
contract SecureVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Checks-Effects-Interactions: State variable updated BEFORE external call
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

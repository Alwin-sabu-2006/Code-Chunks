// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Threat 3: Test Case 1 — Vulnerable withdrawal
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // External call occurs BEFORE balance reset (CEI violation)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
    }
}

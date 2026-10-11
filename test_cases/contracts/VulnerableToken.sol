// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Threat 2: Test Case 1 — Unprotected mint function
contract VulnerableToken {
    uint256 public totalSupply;

    function mint(uint256 amount) public {
        totalSupply += amount;
    }
}

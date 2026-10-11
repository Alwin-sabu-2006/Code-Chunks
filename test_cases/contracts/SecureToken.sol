// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Threat 2: Test Case 2 — Owner-protected mint function
contract SecureToken {
    address public owner;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    function mint(uint256 amount) public onlyOwner {
        totalSupply += amount;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Threat 2: Test Case 3 — Public read function
contract ReadOnlyContract {
    uint256 public totalSupply = 1000000;

    function getSupply() public view returns (uint256) {
        return totalSupply;
    }
}

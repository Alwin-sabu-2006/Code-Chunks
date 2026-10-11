// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CleanVault {
    bytes32 public root;
    function setRoot(bytes32 _root) external {
        root = _root;
    }
}

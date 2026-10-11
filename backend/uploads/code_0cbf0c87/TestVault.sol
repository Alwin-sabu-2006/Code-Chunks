// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TestVault {
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}

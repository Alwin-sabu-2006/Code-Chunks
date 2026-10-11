// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Ballot
 * @notice Decentralized Voting contract with EIP-712 structured signatures
 */
contract Ballot {
    // VULNERABILITY #1: Classical ECDSA OpenZeppelin library usage
    // using ECDSA for bytes32;

    mapping(uint256 => uint256) public proposalVotes;
    mapping(address => bool) public hasVoted;

    bytes32 public constant VOTE_TYPEHASH = keccak256("Vote(uint256 proposalId,address voter)");

    // VULNERABILITY #2: Native ecrecover in structured message flow
    function castVoteBySig(
        uint256 proposalId,
        address voter,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(!hasVoted[voter], "Already voted");

        bytes32 digest = keccak256(abi.encodePacked(VOTE_TYPEHASH, proposalId, voter));
        address signer = ecrecover(digest, v, r, s);
        require(signer == voter, "Invalid vote signature");

        hasVoted[voter] = true;
        proposalVotes[proposalId] += 1;
    }
}

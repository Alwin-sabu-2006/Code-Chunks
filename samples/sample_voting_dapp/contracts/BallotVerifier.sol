// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Sample App 2: Decentralized Voting dApp Ballot Verifier
 * Verifies off-chain voter signatures before recording ballots on-chain.
 */
contract BallotVerifier {
    struct Ballot {
        uint256 proposalId;
        bool voteYes;
        uint256 nonce;
    }

    mapping(address => bool) public hasVoted;
    mapping(uint256 => uint256) public proposalVotes;

    event VoteCast(address indexed voter, uint256 indexed proposalId, bool voteYes);

    /**
     * Planted Pattern 1: EIP-191 message prefix calculation (hash-and-sign)
     */
    function getMessageHash(uint256 proposalId, bool voteYes, uint256 nonce) public pure returns (bytes32) {
        bytes32 rawHash = keccak256(abi.encodePacked(proposalId, voteYes, nonce));
        // Planted Pattern 1: EthSignedMessageHash pattern
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", rawHash));
    }

    /**
     * Cast vote with classical EVM ecrecover signature verification
     */
    function castVote(
        uint256 proposalId,
        bool voteYes,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool) {
        bytes32 messageHash = getMessageHash(proposalId, voteYes, nonce);

        // Planted Pattern 2: Native EVM ecrecover precompile call
        address voter = ecrecover(messageHash, v, r, s);
        require(voter != address(0), "Invalid signature");
        require(!hasVoted[voter], "Voter already cast ballot");

        hasVoted[voter] = true;
        if (voteYes) {
            proposalVotes[proposalId] += 1;
        }

        emit VoteCast(voter, proposalId, voteYes);
        return true;
    }
}

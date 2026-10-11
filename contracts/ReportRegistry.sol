// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ReportRegistry
 * @dev Quantum-Safe Migration Assessment Report Anchoring Contract
 * Stores cryptographic hashes of Q-Chain security assessment reports
 * to guarantee immutable timestamps and tamper-evident verification.
 */
contract ReportRegistry {
    struct Record {
        address submitter;
        uint256 timestamp;
        uint256 blockNumber;
        bool exists;
    }

    // Mapping from report hash (bytes32 keccak256/sha256) to its on-chain record
    mapping(bytes32 => Record) private _records;

    // Track total count of anchored reports
    uint256 public totalAnchored;

    // Array to enumerate anchored hashes for audit trails
    bytes32[] public anchoredHashes;

    // Events
    event Anchored(
        bytes32 indexed reportHash,
        address indexed submitter,
        uint256 timestamp,
        uint256 blockNumber
    );

    // Custom errors
    error ReportAlreadyAnchored(bytes32 reportHash, address existingSubmitter, uint256 existingTimestamp);
    error InvalidReportHash();

    /**
     * @notice Anchors a migration assessment report hash on-chain
     * @param reportHash The 32-byte cryptographic digest of the canonical report JSON
     */
    function anchor(bytes32 reportHash) external returns (bool) {
        if (reportHash == bytes32(0)) {
            revert InvalidReportHash();
        }

        if (_records[reportHash].exists) {
            revert ReportAlreadyAnchored(
                reportHash,
                _records[reportHash].submitter,
                _records[reportHash].timestamp
            );
        }

        Record memory newRecord = Record({
            submitter: msg.sender,
            timestamp: block.timestamp,
            blockNumber: block.number,
            exists: true
        });

        _records[reportHash] = newRecord;
        anchoredHashes.push(reportHash);
        totalAnchored += 1;

        emit Anchored(reportHash, msg.sender, block.timestamp, block.number);
        return true;
    }

    /**
     * @notice Retrieves the anchor record for a given report hash
     * @param reportHash The 32-byte report hash
     * @return submitter Address that anchored the report
     * @return timestamp Block timestamp when anchored
     * @return blockNumber Block number of the anchoring transaction
     * @return exists True if the report has been anchored
     */
    function getRecord(bytes32 reportHash)
        external
        view
        returns (
            address submitter,
            uint256 timestamp,
            uint256 blockNumber,
            bool exists
        )
    {
        Record memory rec = _records[reportHash];
        return (rec.submitter, rec.timestamp, rec.blockNumber, rec.exists);
    }

    /**
     * @notice Checks whether a report hash is anchored
     * @param reportHash The 32-byte report hash
     * @return True if anchored, false otherwise
     */
    function isAnchored(bytes32 reportHash) external view returns (bool) {
        return _records[reportHash].exists;
    }

    /**
     * @notice Returns all anchored hashes
     */
    function getAllAnchoredHashes() external view returns (bytes32[] memory) {
        return anchoredHashes;
    }
}

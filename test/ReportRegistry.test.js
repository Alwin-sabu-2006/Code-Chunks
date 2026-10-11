const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ReportRegistry Smart Contract", function () {
  let reportRegistry;
  let owner;
  let addr1;
  let addr2;

  // Sample keccak256 report hashes
  const sampleHash1 = ethers.keccak256(ethers.toUtf8Bytes("Q-Chain Report 001 - Token Wallet Scan"));
  const sampleHash2 = ethers.keccak256(ethers.toUtf8Bytes("Q-Chain Report 002 - Voting dApp Scan"));
  const sampleHash3 = ethers.keccak256(ethers.toUtf8Bytes("Q-Chain Report 003 - Multisig Scan"));
  const zeroHash = ethers.ZeroHash;

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();
    const ReportRegistryFactory = await ethers.getContractFactory("ReportRegistry");
    reportRegistry = await ReportRegistryFactory.deploy();
    await reportRegistry.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should start with 0 anchored reports", async function () {
      expect(await reportRegistry.totalAnchored()).to.equal(0n);
      const allHashes = await reportRegistry.getAllAnchoredHashes();
      expect(allHashes.length).to.equal(0);
    });

    it("Should report unanchored status for random hashes", async function () {
      expect(await reportRegistry.isAnchored(sampleHash1)).to.be.false;
      const rec = await reportRegistry.getRecord(sampleHash1);
      expect(rec.exists).to.be.false;
      expect(rec.submitter).to.equal(ethers.ZeroAddress);
    });
  });

  describe("Anchoring Functionality", function () {
    it("Should allow anchoring a valid report hash and emit Anchored event", async function () {
      const tx = await reportRegistry.connect(addr1).anchor(sampleHash1);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);

      await expect(tx)
        .to.emit(reportRegistry, "Anchored")
        .withArgs(sampleHash1, addr1.address, block.timestamp, receipt.blockNumber);

      expect(await reportRegistry.totalAnchored()).to.equal(1n);
      expect(await reportRegistry.isAnchored(sampleHash1)).to.be.true;

      const record = await reportRegistry.getRecord(sampleHash1);
      expect(record.submitter).to.equal(addr1.address);
      expect(record.timestamp).to.equal(BigInt(block.timestamp));
      expect(record.blockNumber).to.equal(BigInt(receipt.blockNumber));
      expect(record.exists).to.be.true;
    });

    it("Should reject bytes32(0) with InvalidReportHash error", async function () {
      await expect(
        reportRegistry.connect(addr1).anchor(zeroHash)
      ).to.be.revertedWithCustomError(reportRegistry, "InvalidReportHash");
    });

    it("Should prevent duplicate anchoring of the same report hash", async function () {
      await reportRegistry.connect(addr1).anchor(sampleHash1);

      await expect(
        reportRegistry.connect(addr2).anchor(sampleHash1)
      ).to.be.revertedWithCustomError(reportRegistry, "ReportAlreadyAnchored");
    });

    it("Should correctly track multiple distinct reports", async function () {
      await reportRegistry.connect(addr1).anchor(sampleHash1);
      await reportRegistry.connect(addr2).anchor(sampleHash2);
      await reportRegistry.connect(owner).anchor(sampleHash3);

      expect(await reportRegistry.totalAnchored()).to.equal(3n);
      const all = await reportRegistry.getAllAnchoredHashes();
      expect(all).to.deep.equal([sampleHash1, sampleHash2, sampleHash3]);

      const rec2 = await reportRegistry.getRecord(sampleHash2);
      expect(rec2.submitter).to.equal(addr2.address);
      expect(rec2.exists).to.be.true;
    });
  });
});

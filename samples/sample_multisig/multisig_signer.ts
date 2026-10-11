/**
 * Sample App 3: MultiSig Signer Client
 * Demonstrates Web3 and BitcoinJS secp256k1 key management, threshold signing, and recovery.
 */

import Web3 from "web3";

export class MultiSigSigner {
  private web3: Web3;

  constructor() {
    this.web3 = new Web3();
  }

  /**
   * Generates a new signer keypair using Web3.js
   */
  public generateOwnerAccount() {
    // Planted Pattern 3: web3.eth.accounts.create
    return this.web3.eth.accounts.create();
  }

  /**
   * Signs a multi-sig proposal digest using Web3.js account interface
   */
  public signProposal(privateKey: string, messageHash: string) {
    // Planted Pattern 4: web3.eth.accounts.sign
    const signedData = this.web3.eth.accounts.sign(messageHash, privateKey);
    return signedData.signature;
  }

  /**
   * Recovers signer address from a multi-sig signature
   */
  public recoverSigner(messageHash: string, signature: string) {
    // Planted Pattern 5: web3.eth.accounts.recover
    return this.web3.eth.accounts.recover(messageHash, signature);
  }

  /**
   * Simulates legacy Bitcoin-style co-signer key derivation
   */
  public generateBitcoinCoSigner() {
    // Planted Pattern 6: BitcoinJS / tiny-secp256k1 ECPair creation
    // const keyPair = ECPair.makeRandom();
    const mockSecpCurve = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    return mockSecpCurve;
  }
}

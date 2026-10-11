/**
 * Sample App 1: Quantum-Vulnerable Web3 Token Wallet
 * Demonstrates classical secp256k1 key generation, transaction signing, and EIP-712 auth.
 */

import { ethers } from "ethers";

export interface TransferRequest {
  to: string;
  amount: bigint;
  nonce: number;
}

export class TokenWalletService {
  private wallet: ethers.Wallet;

  constructor(privateKey?: string) {
    if (privateKey) {
      // Planted Pattern 1: Classical secp256k1 key instantiation
      this.wallet = new ethers.Wallet(privateKey);
    } else {
      // Planted Pattern 2: Classical secp256k1 random key generation
      this.wallet = ethers.Wallet.createRandom();
    }
  }

  public getAddress(): string {
    return this.wallet.address;
  }

  /**
   * Derives public key directly using secp256k1 curve point multiplication
   */
  public getRawPublicKey(): string {
    // Planted Pattern 3: Direct elliptic curve signing key usage
    const signingKey = new ethers.SigningKey(this.wallet.privateKey);
    return signingKey.publicKey;
  }

  /**
   * Signs a plain-text authentication challenge
   */
  public async authenticateSession(challenge: string): Promise<string> {
    // Planted Pattern 4: Ethers message signing (personal_sign ECDSA)
    const signature = await this.wallet.signMessage(challenge);
    return signature;
  }

  /**
   * Signs an off-chain EIP-712 structured token transfer authorization
   */
  public async signTransferAuthorization(
    domain: ethers.TypedDataDomain,
    types: Record<string, ethers.TypedDataField[]>,
    transfer: TransferRequest
  ): Promise<string> {
    // Planted Pattern 5: EIP-712 typed data signing
    return await this.wallet.signTypedData(domain, types, transfer);
  }

  /**
   * Authorizes and signs an Ethereum raw transaction payload
   */
  public async signTransactionPayload(tx: ethers.TransactionRequest): Promise<string> {
    // Planted Pattern 6: Classical transaction signing with secp256k1
    return await this.wallet.signTransaction(tx);
  }

  /**
   * Verifies an off-chain signature against an expected address
   */
  public static verifySigner(message: string, signature: string): string {
    // Planted Pattern 7: Classical ECDSA message verification / recovery
    return ethers.verifyMessage(message, signature);
  }
}

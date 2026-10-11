import { ethers } from "ethers";

/**
 * Planted Vulnerability #2 & #3:
 * Client-side signing using classical ethers.Wallet secp256k1 key generation and signMessage
 */
export async function signWithdrawalAuthorization(privateKey: string, amount: string, recipient: string) {
    // VULNERABILITY #2: Classical secp256k1 private key initialization
    const wallet = new ethers.Wallet(privateKey);

    const message = `Authorize withdrawal of ${amount} wei to ${recipient}`;
    
    // VULNERABILITY #3: Classical ECDSA signMessage
    const signature = await wallet.signMessage(message);

    return {
        address: wallet.address,
        message,
        signature
    };
}

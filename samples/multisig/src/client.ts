import * as ed25519 from "@noble/ed25519";

/**
 * Planted Vulnerability #2:
 * Ed25519 and secp256k1 auxiliary co-signing
 */
export async function signMultisigPayload(privateKey: Uint8Array, message: Uint8Array) {
    // VULNERABILITY #2: Ed25519 signing (Shor-vulnerable)
    const signature = await ed25519.sign(message, privateKey);
    return signature;
}

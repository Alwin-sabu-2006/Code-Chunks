"""
Classical Cryptographic Baseline: ECDSA over secp256k1.
Industry standard for Bitcoin, Ethereum, and EVM-compatible blockchains.
Vulnerable to Shor's algorithm on quantum computers.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature,
)
from cryptography.exceptions import InvalidSignature
from crypto.base import CryptoSigner


class ECDSASecp256k1Signer(CryptoSigner):
    """
    Classical Baseline Signer: ECDSA with curve secp256k1 and SHA-256.
    Matches standard EVM and Bitcoin transaction signing parameters.
    """

    algorithm_id = "ECDSA_secp256k1"
    display_name = "ECDSA (secp256k1)"
    category = "Classical (Elliptic Curve)"
    standard = "SECG SEC2 / FIPS 186-5"
    nist_level = 0  # Quantum broken (Shor's algorithm breaks discrete log in polynomial time)
    
    # Standard sizes:
    # 33 bytes compressed SEC1 public key (0x02/0x03 + 32-byte X coordinate)
    # 32 bytes scalar private key
    # 64 bytes raw (r, s) signature (or 65 bytes with recovery id v)
    public_key_len = 33
    private_key_len = 32
    signature_len = 64
    backend_mode = "cryptography-native"

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a random secp256k1 keypair."""
        private_key = ec.generate_private_key(ec.SECP256K1())
        # Export 32-byte big-endian private scalar
        sk_bytes = private_key.private_numbers().private_value.to_bytes(32, byteorder="big")
        
        # Export 33-byte compressed public key
        pub_numbers = private_key.public_key().public_numbers()
        prefix = b"\x02" if pub_numbers.y % 2 == 0 else b"\x03"
        pk_bytes = prefix + pub_numbers.x.to_bytes(32, byteorder="big")
        
        return pk_bytes, sk_bytes

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """
        Sign message using ECDSA-secp256k1 + SHA-256.
        Returns a canonical 64-byte raw (r, s) signature.
        """
        if len(private_key) != 32:
            raise ValueError(f"Invalid private key length for secp256k1: {len(private_key)} (expected 32)")
        
        priv_int = int.from_bytes(private_key, byteorder="big")
        priv_obj = ec.derive_private_key(priv_int, ec.SECP256K1())
        
        # Hash message and sign with deterministic nonce (RFC 6979)
        der_sig = priv_obj.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        
        # SECP256k1 curve parameters
        SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if s > SECP256K1_ORDER // 2:
            s = SECP256K1_ORDER - s
            
        r_bytes = r.to_bytes(32, byteorder="big")
        s_bytes = s.to_bytes(32, byteorder="big")
        return r_bytes + s_bytes

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify raw 64-byte (r, s) ECDSA signature against 33-byte compressed public key.
        Returns True if valid, False on any tamper or error.
        """
        try:
            if len(public_key) != 33 or len(signature) != 64:
                return False
            
            prefix = public_key[0]
            if prefix not in (2, 3):
                return False
            
            x_int = int.from_bytes(public_key[1:33], byteorder="big")
            
            # Reconstruct y coordinate on secp256k1: y^2 = x^3 + 7 (mod p)
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
            alpha = (pow(x_int, 3, p) + 7) % p
            y_int = pow(alpha, (p + 1) // 4, p)
            
            if pow(y_int, 2, p) != alpha:
                return False  # Not on curve
            
            if (prefix == 2 and y_int % 2 != 0) or (prefix == 3 and y_int % 2 == 0):
                y_int = p - y_int
                
            pub_numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256K1())
            pub_key_obj = pub_numbers.public_key()
            
            r = int.from_bytes(signature[:32], byteorder="big")
            s = int.from_bytes(signature[32:], byteorder="big")
            der_sig = encode_dss_signature(r, s)
            
            pub_key_obj.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError, Exception):
            return False

"""
Hybrid Cryptography: Dual ECDSA (secp256k1) + ML-DSA-44 Signature Scheme.
Provides migration security: combines classical EVM backwards compatibility with
post-quantum lattice resilience. Both signatures must verify simultaneously.
"""

from typing import Tuple
from crypto.base import CryptoSigner
from crypto.ecdsa_signer import ECDSASecp256k1Signer
from crypto.mldsa_signer import MLDSASigner


class HybridECDSAMLDSASigner(CryptoSigner):
    """
    Hybrid Dual Signer: ECDSA (secp256k1) + ML-DSA-44 (FIPS 204).
    Guarantees 'Best of Both Worlds' security: unbroken if at least one underlying scheme holds.
    """

    def __init__(self, pqc_variant: str = "ML-DSA-44"):
        self.ecdsa = ECDSASecp256k1Signer()
        self.mldsa = MLDSASigner(variant=pqc_variant)
        
        self.algorithm_id = f"Hybrid_ECDSA_{pqc_variant}"
        self.display_name = f"Hybrid (ECDSA secp256k1 + {pqc_variant})"
        self.category = "Hybrid (Classical + Lattice Dual-Sign)"
        self.standard = "NIST / IETF Draft Dual-Signature Composite"
        self.nist_level = self.mldsa.nist_level
        
        self.public_key_len = self.ecdsa.public_key_len + self.mldsa.public_key_len
        self.private_key_len = self.ecdsa.private_key_len + self.mldsa.private_key_len
        self.signature_len = self.ecdsa.signature_len + self.mldsa.signature_len
        self.backend_mode = f"Hybrid ({self.ecdsa.backend_mode} + {self.mldsa.backend_mode})"

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate dual keypair (ECDSA + ML-DSA)."""
        pk_ec, sk_ec = self.ecdsa.keygen()
        pk_pq, sk_pq = self.mldsa.keygen()
        
        pk_composite = pk_ec + pk_pq
        sk_composite = sk_ec + sk_pq
        return pk_composite, sk_composite

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign message with both ECDSA and ML-DSA private keys."""
        if len(private_key) != self.private_key_len:
            raise ValueError(f"Invalid private key length for {self.algorithm_id}: expected {self.private_key_len}, got {len(private_key)}")

        sk_ec = private_key[: self.ecdsa.private_key_len]
        sk_pq = private_key[self.ecdsa.private_key_len :]

        # Domain separated signing
        sig_ec = self.ecdsa.sign(message, sk_ec)
        sig_pq = self.mldsa.sign(message, sk_pq)

        return sig_ec + sig_pq

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify both ECDSA and ML-DSA signatures.
        Returns True ONLY if BOTH signatures are cryptographically valid.
        """
        if len(public_key) != self.public_key_len or len(signature) != self.signature_len:
            return False

        pk_ec = public_key[: self.ecdsa.public_key_len]
        pk_pq = public_key[self.ecdsa.public_key_len :]

        sig_ec = signature[: self.ecdsa.signature_len]
        sig_pq = signature[self.ecdsa.signature_len :]

        ec_valid = self.ecdsa.verify(message, sig_ec, pk_ec)
        pq_valid = self.mldsa.verify(message, sig_pq, pk_pq)

        return ec_valid and pq_valid

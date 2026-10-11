"""
Base abstract classes and types for all Cryptographic & PQC Signers.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Optional
from schemas.crypto_schemas import KeyPair, SignatureResult


class CryptoSigner(ABC):
    """
    Unified abstract interface for all cryptographic signature algorithms:
    - Classical: ECDSA (secp256k1)
    - Lattice-based: ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
    - Hash-based: SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-256f (FIPS 205)
    - Compact Lattice: Falcon-512, Falcon-1024 (FN-DSA)
    - Hybrid: ECDSA_secp256k1 + ML-DSA dual signatures
    """

    algorithm_id: str
    display_name: str
    category: str
    standard: str
    nist_level: int
    public_key_len: int
    private_key_len: int
    signature_len: int
    backend_mode: str = "reference"  # "liboqs-c" or "reference"

    @abstractmethod
    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generate a new cryptographic keypair.
        Returns:
            (public_key_bytes, private_key_bytes)
        """
        pass

    @abstractmethod
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """
        Sign a message using the private key.
        Returns:
            signature_bytes
        """
        pass

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature against a message and public key.
        Returns:
            True if signature is valid and authentic, False otherwise.
        """
        pass

    def export_keypair(self, pk: bytes, sk: bytes) -> KeyPair:
        """Export keypair as a typed Pydantic KeyPair object."""
        return KeyPair(
            algorithm=self.algorithm_id,
            public_key_hex=pk.hex(),
            private_key_hex=sk.hex(),
            public_key_bytes_len=len(pk),
        )

    def sign_message_result(self, message: bytes, private_key: bytes, public_key: bytes) -> SignatureResult:
        """Sign message and return a typed SignatureResult object."""
        sig = self.sign(message, private_key)
        return SignatureResult(
            algorithm=self.algorithm_id,
            message_hex=message.hex(),
            signature_hex=sig.hex(),
            signature_bytes_len=len(sig),
            public_key_hex=public_key.hex(),
        )

"""Wallet: classical ECDSA (secp256k1) keys and signatures.

INTENTIONALLY QUANTUM-VULNERABLE (demo target for Q-Chain).
Shor's algorithm on a large quantum computer can recover an ECDSA private key
from its public key. Do not use this code in production.
"""
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP256K1()  # FINDING 1: classical elliptic-curve key generation


def address_of(public_bytes: bytes) -> str:
    # DECOY (not quantum-vulnerable): hashing a public key only loses a little
    # security against Grover's algorithm.
    return hashlib.sha256(public_bytes).hexdigest()[:40]


class Wallet:
    def __init__(self, private_key=None):
        self.private_key = private_key or ec.generate_private_key(CURVE)
        self.public_key = self.private_key.public_key()

    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )

    @property
    def address(self) -> str:
        return address_of(self.public_bytes)

    def sign(self, message: bytes) -> bytes:
        # FINDING 2: ECDSA signing with SHA-256
        return self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def verify(public_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, public_bytes)
        pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))  # FINDING 2
        return True
    except (InvalidSignature, ValueError):
        return False

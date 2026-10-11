"""Node identity and peer channel setup.

INTENTIONALLY QUANTUM-VULNERABLE (demo target for Q-Chain):
RSA signatures and elliptic-curve Diffie-Hellman both fall to Shor's algorithm,
and recorded handshakes are exposed to "harvest now, decrypt later".
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class NodeIdentity:
    def __init__(self, name: str):
        self.name = name
        # FINDING 4: RSA-2048 node identity key
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # FINDING 5: ECDH (P-256) key agreement for the peer channel
        self.ecdh_key = ec.generate_private_key(ec.SECP256R1())

    def sign(self, data: bytes) -> bytes:
        return self.rsa_key.sign(data, padding.PKCS1v15(), hashes.SHA256())  # FINDING 4

    def rsa_public(self):
        return self.rsa_key.public_key()

    def ecdh_public_bytes(self) -> bytes:
        return self.ecdh_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    def shared_secret(self, peer_ecdh_public: bytes) -> bytes:
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_ecdh_public)
        raw = self.ecdh_key.exchange(ec.ECDH(), peer)  # FINDING 5
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"vulnchain-peer-channel"
        ).derive(raw)


def verify_peer(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())  # FINDING 4
        return True
    except InvalidSignature:
        return False


def handshake(a: NodeIdentity, b: NodeIdentity) -> bool:
    """Both nodes sign their ECDH public key, verify each other, derive one secret."""
    sig_a, sig_b = a.sign(a.ecdh_public_bytes()), b.sign(b.ecdh_public_bytes())
    if not verify_peer(a.rsa_public(), a.ecdh_public_bytes(), sig_a):
        return False
    if not verify_peer(b.rsa_public(), b.ecdh_public_bytes(), sig_b):
        return False
    return a.shared_secret(b.ecdh_public_bytes()) == b.shared_secret(a.ecdh_public_bytes())

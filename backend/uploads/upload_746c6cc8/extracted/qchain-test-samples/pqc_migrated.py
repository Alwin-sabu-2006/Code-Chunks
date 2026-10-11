"""ALREADY-MIGRATED SAMPLE: uses post-quantum algorithms via liboqs-python.
Expected: zero Shor-vulnerable findings; ideally an informational note that
PQC (ML-DSA, ML-KEM) is already in use. Static sample only, not executed here.
Algorithm names depend on the liboqs version (older builds use Dilithium3 / Kyber768)."""
import oqs


def sign_message(message: bytes):
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)
    return public_key, signature


def verify_message(message: bytes, signature: bytes, public_key: bytes) -> bool:
    with oqs.Signature("ML-DSA-65") as verifier:
        return verifier.verify(message, signature, public_key)


def establish_secret():
    with oqs.KeyEncapsulation("ML-KEM-768") as server:
        public_key = server.generate_keypair()
        with oqs.KeyEncapsulation("ML-KEM-768") as client:
            ciphertext, client_secret = client.encap_secret(public_key)
        server_secret = server.decap_secret(ciphertext)
    return client_secret == server_secret

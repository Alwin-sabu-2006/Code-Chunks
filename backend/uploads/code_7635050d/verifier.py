
"""CONTROL SAMPLE: no public-key cryptography at all.
Expected: analyzed successfully, zero quantum findings (state: clean).
Hashes, HMAC and 256-bit symmetric encryption are not Shor-vulnerable."""
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def fingerprint(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def tag(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def seal(key32: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key32).encrypt(nonce, plaintext, None)
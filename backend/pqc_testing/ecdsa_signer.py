"""
ECDSA (secp256k1) Classical Baseline Signer.
Standard blockchain elliptic curve signature scheme (used in Bitcoin & Ethereum).
Part of Q-Chain Platform (Member 2 Deliverable).
"""

from typing import Optional
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    load_pem_public_key,
    load_pem_private_key,
)

from .base import (
    BaseSignatureScheme,
    KeyPair,
    ParameterSetId,
    SignatureResult,
    VerificationOutcome,
)


class ECDSABaselineSigner(BaseSignatureScheme):
    """
    Classical ECDSA signature scheme over secp256k1 curve.
    Uses SHA-256 digest, emitting compact 64-byte raw (r, s) or DER signatures.
    """

    def __init__(self, use_raw_rs_format: bool = True):
        self._param_id = ParameterSetId.ECDSA_SECP256K1
        self._curve = ec.SECP256K1()
        self._use_raw_rs_format = use_raw_rs_format

    @property
    def algorithm(self) -> ParameterSetId:
        return self._param_id

    def generate_keypair(self) -> KeyPair:
        """
        Generate secp256k1 private and public keys.
        Public key is exported as uncompressed 65-byte SEC1 format (0x04 || X || Y)
        or 33-byte compressed format. Here we export raw 65-byte uncompressed point.
        """
        private_key_obj = ec.generate_private_key(self._curve)
        public_key_obj = private_key_obj.public_key()

        # Export SEC1 uncompressed public key (standard 65 bytes)
        public_bytes = public_key_obj.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint,
        )

        # Export private key as 32-byte big-endian scalar
        private_bytes = private_key_obj.private_numbers().private_value.to_bytes(
            32, byteorder="big"
        )

        return KeyPair(
            algorithm=self._param_id,
            public_key=public_bytes,
            private_key=private_bytes,
        )

    def sign(self, private_key: bytes, message: bytes) -> SignatureResult:
        """
        Sign message using secp256k1 private key.
        Emits 64-byte compact signature (r || s, 32 bytes each) standard in Ethereum/Bitcoin.
        """
        if len(private_key) != 32:
            raise ValueError(
                f"Invalid ECDSA secp256k1 private key: expected 32 bytes, got {len(private_key)}"
            )

        priv_int = int.from_bytes(private_key, byteorder="big")
        private_key_obj = ec.derive_private_key(priv_int, self._curve)

        t0 = time.perf_counter_ns()
        der_signature = private_key_obj.sign(
            message,
            ec.ECDSA(hashes.SHA256()),
        )
        t1 = time.perf_counter_ns()

        if self._use_raw_rs_format:
            r, s = decode_dss_signature(der_signature)
            raw_sig = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
            sig_bytes = raw_sig
        else:
            sig_bytes = der_signature

        duration_ms = (t1 - t0) / 1_000_000.0

        return SignatureResult(
            algorithm=self._param_id,
            signature=sig_bytes,
            message=message,
            duration_ms=duration_ms,
        )

    def verify(
        self, public_key: bytes, message: bytes, signature: bytes
    ) -> VerificationOutcome:
        """
        Verify ECDSA secp256k1 signature against public key.
        Supports both 64-byte raw (r || s) and standard ASN.1 DER format.
        """
        t0 = time.perf_counter_ns()
        try:
            public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                self._curve, public_key
            )
        except Exception as ex:
            t1 = time.perf_counter_ns()
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=False,
                duration_ms=(t1 - t0) / 1_000_000.0,
                error_message=f"Invalid public key point: {str(ex)}",
            )

        # Convert 64-byte raw signature to DER if needed
        der_signature = signature
        if len(signature) == 64:
            try:
                r = int.from_bytes(signature[:32], byteorder="big")
                s = int.from_bytes(signature[32:], byteorder="big")
                der_signature = encode_dss_signature(r, s)
            except Exception as ex:
                t1 = time.perf_counter_ns()
                return VerificationOutcome(
                    algorithm=self._param_id,
                    valid=False,
                    duration_ms=(t1 - t0) / 1_000_000.0,
                    error_message=f"Failed to decode 64-byte (r,s) signature: {str(ex)}",
                )

        try:
            public_key_obj.verify(
                der_signature,
                message,
                ec.ECDSA(hashes.SHA256()),
            )
            t1 = time.perf_counter_ns()
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=True,
                duration_ms=(t1 - t0) / 1_000_000.0,
                error_message=None,
            )
        except InvalidSignature:
            t1 = time.perf_counter_ns()
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=False,
                duration_ms=(t1 - t0) / 1_000_000.0,
                error_message="ECDSA signature verification failed: invalid signature",
            )
        except Exception as ex:
            t1 = time.perf_counter_ns()
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=False,
                duration_ms=(t1 - t0) / 1_000_000.0,
                error_message=f"ECDSA verification exception: {type(ex).__name__}: {str(ex)}",
            )

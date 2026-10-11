"""
ML-DSA (Module-Lattice-Based Digital Signature Algorithm - NIST FIPS 204)
Implementation for Q-Chain Platform.
"""

from typing import Any, Dict, Type
import time

try:
    from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5
except ImportError as e:
    raise ImportError(
        "dilithium-py is required for ML-DSA implementation. Install via 'pip install dilithium-py'"
    ) from e

from .base import (
    BaseSignatureScheme,
    KeyPair,
    ParameterSetId,
    SignatureResult,
    VerificationOutcome,
)


class MLDSASigner(BaseSignatureScheme):
    """
    Standardized NIST FIPS 204 ML-DSA digital signature engine.
    Supports ML-DSA-44 (Dilithium2), ML-DSA-65 (Dilithium3), and ML-DSA-87 (Dilithium5).
    """

    _ALGORITHM_MAP: Dict[ParameterSetId, Any] = {
        ParameterSetId.ML_DSA_44: Dilithium2,
        ParameterSetId.ML_DSA_65: Dilithium3,
        ParameterSetId.ML_DSA_87: Dilithium5,
    }

    # Standard expected byte lengths according to NIST FIPS 204 / Dilithium specifications
    EXPECTED_SIZES = {
        ParameterSetId.ML_DSA_44: {
            "pk_bytes": 1312,
            "sk_bytes": 2528,  # internal representation
            "sig_bytes": 2420,
        },
        ParameterSetId.ML_DSA_65: {
            "pk_bytes": 1952,
            "sk_bytes": 4000,
            "sig_bytes": 3293,
        },
        ParameterSetId.ML_DSA_87: {
            "pk_bytes": 2592,
            "sk_bytes": 4864,
            "sig_bytes": 4595,
        },
    }

    def __init__(self, parameter_set: ParameterSetId = ParameterSetId.ML_DSA_44):
        if parameter_set not in self._ALGORITHM_MAP:
            raise ValueError(
                f"Unsupported parameter set {parameter_set}. Must be one of: "
                f"{[p.value for p in self._ALGORITHM_MAP.keys()]}"
            )
        self._param_id = parameter_set
        self._engine = self._ALGORITHM_MAP[parameter_set]

    @property
    def algorithm(self) -> ParameterSetId:
        return self._param_id

    def generate_keypair(self) -> KeyPair:
        """
        Generate a fresh public and private keypair for the selected ML-DSA parameter set.
        """
        t0 = time.perf_counter_ns()
        pk, sk = self._engine.keygen()
        t1 = time.perf_counter_ns()

        return KeyPair(
            algorithm=self._param_id,
            public_key=pk,
            private_key=sk,
        )

    def sign(self, private_key: bytes, message: bytes) -> SignatureResult:
        """
        Sign message using ML-DSA private key.
        """
        if not isinstance(private_key, (bytes, bytearray)):
            raise TypeError("private_key must be bytes or bytearray")
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes or bytearray")

        expected_sk_len = self.EXPECTED_SIZES[self._param_id]["sk_bytes"]
        if len(private_key) != expected_sk_len:
            raise ValueError(
                f"Invalid private key size for {self._param_id.value}: "
                f"got {len(private_key)} bytes, expected {expected_sk_len} bytes"
            )

        t0 = time.perf_counter_ns()
        signature = self._engine.sign(bytes(private_key), bytes(message))
        t1 = time.perf_counter_ns()
        duration_ms = (t1 - t0) / 1_000_000.0

        return SignatureResult(
            algorithm=self._param_id,
            signature=signature,
            message=bytes(message),
            duration_ms=duration_ms,
        )

    def verify(
        self, public_key: bytes, message: bytes, signature: bytes
    ) -> VerificationOutcome:
        """
        Verify signature against public key and message.
        Safely traps formatting errors and returns structured verification outcome.
        """
        if not isinstance(public_key, (bytes, bytearray)):
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=False,
                duration_ms=0.0,
                error_message="public_key must be bytes or bytearray",
            )
        if not isinstance(message, (bytes, bytearray)):
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=False,
                duration_ms=0.0,
                error_message="message must be bytes or bytearray",
            )
        if not isinstance(signature, (bytes, bytearray)):
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=False,
                duration_ms=0.0,
                error_message="signature must be bytes or bytearray",
            )

        expected_pk_len = self.EXPECTED_SIZES[self._param_id]["pk_bytes"]
        if len(public_key) != expected_pk_len:
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=False,
                duration_ms=0.0,
                error_message=(
                    f"Public key length mismatch: got {len(public_key)} bytes, "
                    f"expected {expected_pk_len} bytes for {self._param_id.value}"
                ),
            )

        expected_sig_len = self.EXPECTED_SIZES[self._param_id]["sig_bytes"]
        if len(signature) != expected_sig_len:
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=False,
                duration_ms=0.0,
                error_message=(
                    f"Signature length mismatch: got {len(signature)} bytes, "
                    f"expected {expected_sig_len} bytes for {self._param_id.value}"
                ),
            )

        t0 = time.perf_counter_ns()
        try:
            valid = bool(
                self._engine.verify(
                    bytes(public_key), bytes(message), bytes(signature)
                )
            )
            t1 = time.perf_counter_ns()
            duration_ms = (t1 - t0) / 1_000_000.0
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=valid,
                duration_ms=duration_ms,
                error_message=None if valid else "Signature verification failed mathematically",
            )
        except Exception as ex:
            t1 = time.perf_counter_ns()
            duration_ms = (t1 - t0) / 1_000_000.0
            return VerificationOutcome(
                algorithm=self._param_id,
                valid=False,
                duration_ms=duration_ms,
                error_message=f"Verification exception: {type(ex).__name__}: {str(ex)}",
            )

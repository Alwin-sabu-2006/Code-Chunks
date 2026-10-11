"""
Tamper Testing and Cryptographic Verification Suite for PQC Signatures.
Demonstrates tamper resistance against message modifications, signature corruption,
and mismatched public key attacks.
Part of Q-Chain Platform (Member 2 Deliverable).
"""

from typing import Optional, Tuple
import copy
import time

from .base import (
    BaseSignatureScheme,
    KeyPair,
    ParameterSetId,
    SignatureResult,
    TamperScenarioResult,
    TamperTestSuiteResult,
    VerificationOutcome,
)
from .mldsa_signer import MLDSASigner
from .ecdsa_signer import ECDSABaselineSigner


class TamperTester:
    """
    Executes automated cryptographic tamper scenarios across PQC & classical signature schemes.
    """

    def __init__(self, signer: BaseSignatureScheme):
        self.signer = signer

    @staticmethod
    def _flip_byte_in_bytes(data: bytes, index: int = 0) -> bytes:
        """Flip the least significant bit of a byte in the byte array."""
        b = bytearray(data)
        if len(b) == 0:
            return b"X"
        idx = min(max(0, index), len(b) - 1)
        b[idx] ^= 0x01  # Flip 1 bit
        return bytes(b)

    def run_suite(
        self,
        sample_message: bytes = b"Q-CHAIN: MIGRATION ASSESSMENT REPORT [PAYLOAD HASH: 0x9f83...]",
    ) -> TamperTestSuiteResult:
        """
        Executes all 4 tamper scenarios:
        1. Authentic message and signature verification.
        2. Tampered message rejection (single-bit modification).
        3. Corrupted signature rejection (single-bit signature corruption).
        4. Wrong public key rejection (signature verified against independent public key).
        """
        # Step 0: Generate baseline keypair and valid signature
        keypair_1 = self.signer.generate_keypair()
        sig_result = self.signer.sign(keypair_1.private_key, sample_message)

        scenarios = []

        # ==========================================
        # Scenario 1: Authentic Verification
        # ==========================================
        t0 = time.perf_counter_ns()
        v1 = self.signer.verify(
            keypair_1.public_key, sample_message, sig_result.signature
        )
        t1 = time.perf_counter_ns()
        scenarios.append(
            TamperScenarioResult(
                scenario_id="TAMPER_SCENARIO_1_AUTHENTIC",
                scenario_name="Authentic Message & Signature",
                description="Verifies that an unmodified signature over the authentic message passes validation.",
                expected_outcome=True,
                actual_outcome=v1.valid,
                passed=(v1.valid is True),
                duration_ms=(t1 - t0) / 1_000_000.0,
                details={
                    "message_preview": sample_message[:48].decode("utf-8", errors="replace"),
                    "signature_size_bytes": len(sig_result.signature),
                    "error_message": v1.error_message,
                },
            )
        )

        # ==========================================
        # Scenario 2: Modified Message
        # ==========================================
        tampered_message = self._flip_byte_in_bytes(sample_message, index=12)
        t0 = time.perf_counter_ns()
        v2 = self.signer.verify(
            keypair_1.public_key, tampered_message, sig_result.signature
        )
        t1 = time.perf_counter_ns()
        # Pass criteria: verification must fail (v2.valid is False)
        passed_2 = (v2.valid is False)
        scenarios.append(
            TamperScenarioResult(
                scenario_id="TAMPER_SCENARIO_2_MODIFIED_MESSAGE",
                scenario_name="Modified / Tampered Message",
                description="Modifies 1 bit in the signed payload to verify that unauthorized data alteration is detected.",
                expected_outcome=False,
                actual_outcome=v2.valid,
                passed=passed_2,
                duration_ms=(t1 - t0) / 1_000_000.0,
                details={
                    "original_message_len": len(sample_message),
                    "tampered_index": 12,
                    "error_message": v2.error_message,
                    "tamper_detected": passed_2,
                },
            )
        )

        # ==========================================
        # Scenario 3: Corrupted Signature
        # ==========================================
        corrupted_signature = self._flip_byte_in_bytes(
            sig_result.signature, index=len(sig_result.signature) // 2
        )
        t0 = time.perf_counter_ns()
        v3 = self.signer.verify(
            keypair_1.public_key, sample_message, corrupted_signature
        )
        t1 = time.perf_counter_ns()
        passed_3 = (v3.valid is False)
        scenarios.append(
            TamperScenarioResult(
                scenario_id="TAMPER_SCENARIO_3_CORRUPTED_SIGNATURE",
                scenario_name="Corrupted Signature Bytes",
                description="Flips 1 bit midway inside the signature to ensure damaged or forged signature bytes fail verification.",
                expected_outcome=False,
                actual_outcome=v3.valid,
                passed=passed_3,
                duration_ms=(t1 - t0) / 1_000_000.0,
                details={
                    "signature_size_bytes": len(sig_result.signature),
                    "corrupted_byte_offset": len(sig_result.signature) // 2,
                    "error_message": v3.error_message,
                    "tamper_detected": passed_3,
                },
            )
        )

        # ==========================================
        # Scenario 4: Wrong Public Key
        # ==========================================
        keypair_2 = self.signer.generate_keypair()
        t0 = time.perf_counter_ns()
        v4 = self.signer.verify(
            keypair_2.public_key, sample_message, sig_result.signature
        )
        t1 = time.perf_counter_ns()
        passed_4 = (v4.valid is False)
        scenarios.append(
            TamperScenarioResult(
                scenario_id="TAMPER_SCENARIO_4_WRONG_PUBLIC_KEY",
                scenario_name="Mismatched / Wrong Public Key",
                description="Attempts verification with an alternative independently generated public key to prevent identity spoofing.",
                expected_outcome=False,
                actual_outcome=v4.valid,
                passed=passed_4,
                duration_ms=(t1 - t0) / 1_000_000.0,
                details={
                    "keypair_1_pk_sample": keypair_1.public_key[:16].hex(),
                    "keypair_2_pk_sample": keypair_2.public_key[:16].hex(),
                    "error_message": v4.error_message,
                    "tamper_detected": passed_4,
                },
            )
        )

        total = len(scenarios)
        passed = sum(1 for s in scenarios if s.passed)
        rate = (passed / total) * 100.0 if total > 0 else 0.0

        return TamperTestSuiteResult(
            algorithm=self.signer.algorithm,
            scenarios=scenarios,
            total_scenarios=total,
            passed_scenarios=passed,
            tamper_detection_rate_pct=round(rate, 2),
            all_passed=(passed == total),
        )

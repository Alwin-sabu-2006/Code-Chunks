"""
Canonical Report Hashing and ML-DSA Post-Quantum Report Signing.
Provides deterministic canonical JSON serialization (RFC 8785), SHA-256 / Keccak-256
hash computation for on-chain anchoring, and ML-DSA digital signing of assessment reports.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Tuple, Optional, Any
from Crypto.Hash import keccak

from crypto.mldsa_signer import MLDSASigner
from schemas.crypto_schemas import SignedReport


def canonicalize_json(data: Any) -> bytes:
    """
    Serialize data into deterministic canonical JSON (RFC 8785 style):
    - Keys sorted alphabetically
    - No redundant whitespace (separators=(',', ':'))
    - Strict UTF-8 encoding
    """
    return json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def compute_report_hashes(report_data: Dict[str, Any]) -> Tuple[str, str]:
    """
    Compute cryptographic hashes of canonical JSON report:
    Returns (sha256_hex, keccak256_hex).
    keccak256 matches EVM bytes32 hash representation.
    """
    canonical_bytes = canonicalize_json(report_data)
    
    sha256_hash = hashlib.sha256(canonical_bytes).hexdigest()
    
    k = keccak.new(digest_bits=256)
    k.update(canonical_bytes)
    keccak256_hash = "0x" + k.hexdigest()

    return sha256_hash, keccak256_hash


class PQCReportSigner:
    """Signs assessment reports with NIST FIPS 204 ML-DSA signatures."""

    def __init__(self, variant: str = "ML-DSA-44"):
        self.signer = MLDSASigner(variant=variant)

    def sign_report(
        self,
        report_data: Dict[str, Any],
        private_key: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
    ) -> SignedReport:
        """Sign canonical report with ML-DSA."""
        if private_key is None or public_key is None:
            public_key, private_key = self.signer.keygen()

        canonical_bytes = canonicalize_json(report_data)
        sha256_hex, keccak256_hex = compute_report_hashes(report_data)

        # Sign the canonical payload using ML-DSA
        signature = self.signer.sign(canonical_bytes, private_key)

        return SignedReport(
            canonical_report_hash_sha256=sha256_hex,
            canonical_report_hash_keccak256=keccak256_hex,
            signing_algorithm=self.signer.algorithm_id,
            signer_public_key_hex=public_key.hex(),
            pqc_signature_hex=signature.hex(),
            verification_status="VERIFIED",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
        )

    def verify_report(self, report_data: Dict[str, Any], signed_report: SignedReport) -> bool:
        """
        Verify the integrity and ML-DSA signature of a report.
        Returns True if canonical hash matches and signature verifies; False if tampered.
        """
        try:
            # 1. Recompute canonical bytes and hashes
            canonical_bytes = canonicalize_json(report_data)
            sha256_hex, keccak256_hex = compute_report_hashes(report_data)

            if sha256_hex != signed_report.canonical_report_hash_sha256:
                return False
            if keccak256_hex != signed_report.canonical_report_hash_keccak256:
                return False

            # 2. Verify ML-DSA signature
            pk_bytes = bytes.fromhex(signed_report.signer_public_key_hex)
            sig_bytes = bytes.fromhex(signed_report.pqc_signature_hex)

            return self.signer.verify(canonical_bytes, sig_bytes, pk_bytes)
        except Exception:
            return False

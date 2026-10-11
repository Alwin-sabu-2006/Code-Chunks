"""
Central Cryptographic Algorithm Registry & Factory.
Provides discovery, instantiation, and metadata lookup for all supported algorithms.
"""

from typing import Dict, List, Type, Optional
from crypto.base import CryptoSigner
from crypto.ecdsa_signer import ECDSASecp256k1Signer
from crypto.mldsa_signer import MLDSASigner
from crypto.slhdsa_signer import SLHDSASigner
from crypto.falcon_signer import FalconSigner
from crypto.hybrid_signer import HybridECDSAMLDSASigner


class CryptoRegistry:
    """Registry managing all classical, PQC, and hybrid signing algorithms."""

    _SIGNERS: Dict[str, CryptoSigner] = {}

    @classmethod
    def initialize(cls):
        """Register all algorithm instances."""
        if cls._SIGNERS:
            return

        instances: List[CryptoSigner] = [
            ECDSASecp256k1Signer(),
            MLDSASigner(variant="ML-DSA-44"),
            MLDSASigner(variant="ML-DSA-65"),
            MLDSASigner(variant="ML-DSA-87"),
            SLHDSASigner(variant="SLH-DSA-SHAKE-128f"),
            SLHDSASigner(variant="SLH-DSA-SHAKE-128s"),
            SLHDSASigner(variant="SLH-DSA-SHAKE-256f"),
            FalconSigner(variant="Falcon-512"),
            FalconSigner(variant="Falcon-1024"),
            HybridECDSAMLDSASigner(pqc_variant="ML-DSA-44"),
            HybridECDSAMLDSASigner(pqc_variant="ML-DSA-65"),
        ]

        for s in instances:
            cls._SIGNERS[s.algorithm_id] = s

    @classmethod
    def get_signer(cls, algorithm_id: str) -> CryptoSigner:
        """Get signer instance by algorithm ID."""
        cls.initialize()
        # Case-insensitive or normalized matching
        for k, v in cls._SIGNERS.items():
            if k.lower() == algorithm_id.lower().replace("-", "_") or k.lower() == algorithm_id.lower():
                return v
        if algorithm_id in cls._SIGNERS:
            return cls._SIGNERS[algorithm_id]
        raise ValueError(
            f"Unsupported algorithm '{algorithm_id}'. Supported algorithms: {list(cls._SIGNERS.keys())}"
        )

    @classmethod
    def list_algorithms(cls) -> List[str]:
        """List all available algorithm identifiers."""
        cls.initialize()
        return list(cls._SIGNERS.keys())

    @classmethod
    def get_all_signers(cls) -> List[CryptoSigner]:
        """Get all signer instances."""
        cls.initialize()
        return list(cls._SIGNERS.values())

    @classmethod
    def get_summary_table(cls) -> List[Dict]:
        """Get summary metadata table for all algorithms."""
        cls.initialize()
        summary = []
        for s in cls._SIGNERS.values():
            summary.append({
                "algorithm_id": s.algorithm_id,
                "display_name": s.display_name,
                "category": s.category,
                "standard": s.standard,
                "nist_level": s.nist_level,
                "public_key_bytes": s.public_key_len,
                "signature_bytes": s.signature_len,
                "backend_mode": s.backend_mode,
            })
        return summary

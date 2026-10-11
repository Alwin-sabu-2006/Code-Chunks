"""
Base cryptographic abstractions and data models for PQC Signature Testing.
Part of Q-Chain Platform (Member 2 Deliverable).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import base64
import time


class AlgorithmFamily(str, Enum):
    PQC_LATTICE = "Post-Quantum Lattice-Based"
    CLASSICAL_ECC = "Classical Elliptic Curve"


class ParameterSetId(str, Enum):
    ML_DSA_44 = "ML-DSA-44"  # NIST FIPS 204 (Dilithium2, Security Category 2)
    ML_DSA_65 = "ML-DSA-65"  # NIST FIPS 204 (Dilithium3, Security Category 3)
    ML_DSA_87 = "ML-DSA-87"  # NIST FIPS 204 (Dilithium5, Security Category 5)
    ECDSA_SECP256K1 = "ECDSA-secp256k1"  # Classical baseline for blockchain transactions


@dataclass
class AlgorithmMetadata:
    id: ParameterSetId
    name: str
    standard: str
    family: AlgorithmFamily
    nist_security_level: int
    quantum_safe: bool
    claimed_security: str
    description: str


ALGORITHM_CATALOG: Dict[ParameterSetId, AlgorithmMetadata] = {
    ParameterSetId.ML_DSA_44: AlgorithmMetadata(
        id=ParameterSetId.ML_DSA_44,
        name="ML-DSA-44 (Dilithium2)",
        standard="NIST FIPS 204",
        family=AlgorithmFamily.PQC_LATTICE,
        nist_security_level=2,
        quantum_safe=True,
        claimed_security="Equivalent to SHA-256 / AES-128 collision resistance against quantum & classical attacks",
        description="Module-Lattice-Based Digital Signature Algorithm (Category 2). Best balance of size and performance for general signing.",
    ),
    ParameterSetId.ML_DSA_65: AlgorithmMetadata(
        id=ParameterSetId.ML_DSA_65,
        name="ML-DSA-65 (Dilithium3)",
        standard="NIST FIPS 204",
        family=AlgorithmFamily.PQC_LATTICE,
        nist_security_level=3,
        quantum_safe=True,
        claimed_security="Equivalent to AES-192 security level against classical and quantum cryptanalysis",
        description="Recommended default parameter set for high-security applications.",
    ),
    ParameterSetId.ML_DSA_87: AlgorithmMetadata(
        id=ParameterSetId.ML_DSA_87,
        name="ML-DSA-87 (Dilithium5)",
        standard="NIST FIPS 204",
        family=AlgorithmFamily.PQC_LATTICE,
        nist_security_level=5,
        quantum_safe=True,
        claimed_security="Equivalent to AES-256 security level against classical and quantum cryptanalysis",
        description="Maximum security parameter set for long-lived sensitive signatures.",
    ),
    ParameterSetId.ECDSA_SECP256K1: AlgorithmMetadata(
        id=ParameterSetId.ECDSA_SECP256K1,
        name="ECDSA (secp256k1)",
        standard="SEC 2 / ANSI X9.62",
        family=AlgorithmFamily.CLASSICAL_ECC,
        nist_security_level=1,
        quantum_safe=False,
        claimed_security="128-bit classical security; 0-bit quantum security against Shor's algorithm",
        description="Standard blockchain signature scheme used in Bitcoin and Ethereum. Vulnerable to polynomial-time quantum forgery.",
    ),
}


@dataclass
class KeyPair:
    algorithm: ParameterSetId
    public_key: bytes
    private_key: bytes

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key).decode("utf-8")

    @property
    def public_key_size(self) -> int:
        return len(self.public_key)

    @property
    def private_key_size(self) -> int:
        return len(self.private_key)

    def to_dict(self, include_private: bool = False) -> Dict[str, Any]:
        data = {
            "algorithm": self.algorithm.value,
            "public_key_hex": self.public_key_hex,
            "public_key_b64": self.public_key_b64,
            "public_key_size_bytes": self.public_key_size,
            "private_key_size_bytes": self.private_key_size,
        }
        if include_private:
            data["private_key_hex"] = self.private_key.hex()
            data["private_key_b64"] = base64.b64encode(self.private_key).decode("utf-8")
        return data


@dataclass
class SignatureResult:
    algorithm: ParameterSetId
    signature: bytes
    message: bytes
    duration_ms: float

    @property
    def signature_hex(self) -> str:
        return self.signature.hex()

    @property
    def signature_b64(self) -> str:
        return base64.b64encode(self.signature).decode("utf-8")

    @property
    def signature_size(self) -> int:
        return len(self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm.value,
            "signature_hex": self.signature_hex,
            "signature_b64": self.signature_b64,
            "signature_size_bytes": self.signature_size,
            "duration_ms": round(self.duration_ms, 4),
        }


@dataclass
class VerificationOutcome:
    algorithm: ParameterSetId
    valid: bool
    duration_ms: float
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm.value,
            "valid": self.valid,
            "duration_ms": round(self.duration_ms, 4),
            "error_message": self.error_message,
        }


@dataclass
class TamperScenarioResult:
    scenario_id: str
    scenario_name: str
    description: str
    expected_outcome: bool
    actual_outcome: bool
    passed: bool
    duration_ms: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "description": self.description,
            "expected_outcome": self.expected_outcome,
            "actual_outcome": self.actual_outcome,
            "passed": self.passed,
            "duration_ms": round(self.duration_ms, 4),
            "details": self.details,
        }


@dataclass
class TamperTestSuiteResult:
    algorithm: ParameterSetId
    scenarios: List[TamperScenarioResult]
    total_scenarios: int
    passed_scenarios: int
    tamper_detection_rate_pct: float
    all_passed: bool
    tested_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm.value,
            "total_scenarios": self.total_scenarios,
            "passed_scenarios": self.passed_scenarios,
            "tamper_detection_rate_pct": self.tamper_detection_rate_pct,
            "all_passed": self.all_passed,
            "tested_at": self.tested_at,
            "scenarios": [s.to_dict() for s in self.scenarios],
        }


class BaseSignatureScheme(ABC):
    """Abstract interface for signature algorithms."""

    @property
    @abstractmethod
    def algorithm(self) -> ParameterSetId:
        """Returns the algorithm identifier."""
        pass

    @abstractmethod
    def generate_keypair(self) -> KeyPair:
        """Generates a public/private keypair."""
        pass

    @abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> SignatureResult:
        """Signs a message using the private key."""
        pass

    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> VerificationOutcome:
        """Verifies a signature against the public key and message."""
        pass

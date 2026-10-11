"""
Q-Chain Post-Quantum Cryptography Signature Testing Module (Member 2).
Exposes ML-DSA (FIPS 204), ECDSA baseline, Tamper Testing Suite,
Performance Benchmarking Harness, and FastAPI Router.
"""

from .base import (
    ALGORITHM_CATALOG,
    AlgorithmFamily,
    AlgorithmMetadata,
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
from .tamper_tester import TamperTester
from .benchmarker import (
    BenchmarkReport,
    OnChainCostEstimate,
    PQCBenchmarker,
    TimingStats,
)
from .router import router as pqc_router

__all__ = [
    "ALGORITHM_CATALOG",
    "AlgorithmFamily",
    "AlgorithmMetadata",
    "BaseSignatureScheme",
    "KeyPair",
    "ParameterSetId",
    "SignatureResult",
    "TamperScenarioResult",
    "TamperTestSuiteResult",
    "VerificationOutcome",
    "MLDSASigner",
    "ECDSABaselineSigner",
    "TamperTester",
    "PQCBenchmarker",
    "BenchmarkReport",
    "OnChainCostEstimate",
    "TimingStats",
    "pqc_router",
]

"""
Crypto and PQC Data Schemas for Q-Chain Platform.
Defines typed models for keys, signatures, benchmarks, verification results,
gas estimates, and algorithm recommendations according to the shared schema agreement.
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class KeyPair(BaseModel):
    algorithm: str = Field(..., description="Algorithm name, e.g. ECDSA_secp256k1, ML-DSA-44")
    public_key_hex: str = Field(..., description="Hex-encoded public key")
    private_key_hex: str = Field(..., description="Hex-encoded private key")
    public_key_bytes_len: int = Field(..., description="Length of public key in bytes")


class SignatureResult(BaseModel):
    algorithm: str = Field(..., description="Algorithm name used for signing")
    message_hex: str = Field(..., description="Hex-encoded message that was signed")
    signature_hex: str = Field(..., description="Hex-encoded signature")
    signature_bytes_len: int = Field(..., description="Length of signature in bytes")
    public_key_hex: str = Field(..., description="Hex-encoded public key")


class VerificationScenarioResult(BaseModel):
    scenario_name: str = Field(..., description="Name of test scenario: valid, tampered_message, tampered_signature, wrong_key")
    expected_valid: bool = Field(..., description="Expected verification result")
    actual_valid: bool = Field(..., description="Actual verification result")
    passed_test: bool = Field(..., description="True if actual_valid == expected_valid")
    details: str = Field(default="", description="Scenario description or notes")


class AlgorithmVerificationResult(BaseModel):
    algorithm: str = Field(..., description="Algorithm tested")
    standard_name: str = Field(..., description="Standard name (e.g., FIPS 204 ML-DSA)")
    category: str = Field(..., description="Classical, Lattice-based, Hash-based, NTRU, Hybrid")
    nist_security_level: int = Field(..., description="NIST Security Level (0 for classical, 1, 2, 3, 5 for PQC)")
    scenarios: List[VerificationScenarioResult] = Field(default_factory=list)
    tamper_detection_rate_pct: float = Field(..., description="Percentage of tamper scenarios successfully caught (100.0%)")
    all_tests_passed: bool = Field(..., description="True if all 4 tamper tests passed")


class VerificationMatrix(BaseModel):
    timestamp_utc: str = Field(..., description="ISO 8601 Timestamp of verification run")
    overall_tamper_detection_rate_pct: float = Field(..., description="Average tamper detection rate across all algos")
    algorithms_tested: List[str] = Field(default_factory=list)
    results: List[AlgorithmVerificationResult] = Field(default_factory=list)


class AlgorithmBenchmarkMetrics(BaseModel):
    algorithm: str = Field(..., description="Algorithm identifier")
    display_name: str = Field(..., description="Human readable name")
    category: str = Field(..., description="Classical, Lattice (MLWE), Hash-based, NTRU, Hybrid")
    standard: str = Field(..., description="Standard reference e.g. SECG SEC2 / NIST FIPS 204")
    nist_level: int = Field(..., description="NIST Security Level")
    
    # Sizes
    public_key_bytes: int = Field(..., description="Public key size in bytes")
    private_key_bytes: int = Field(..., description="Private key size in bytes")
    signature_bytes: int = Field(..., description="Signature size in bytes")
    message_bytes: int = Field(..., description="Benchmarked message size in bytes")
    
    # Timings in nanoseconds
    iterations: int = Field(..., description="Number of timed iterations")
    keygen_mean_ns: float = Field(..., description="Mean key generation time in ns")
    keygen_std_dev_ns: float = Field(..., description="Keygen standard deviation in ns")
    sign_mean_ns: float = Field(..., description="Mean signing time in ns")
    sign_std_dev_ns: float = Field(..., description="Signing standard deviation in ns")
    verify_mean_ns: float = Field(..., description="Mean verification time in ns")
    verify_std_dev_ns: float = Field(..., description="Verification standard deviation in ns")
    
    # Convenience millisecond fields for frontend rendering
    keygen_mean_ms: float = Field(..., description="Keygen time in milliseconds")
    sign_mean_ms: float = Field(..., description="Sign time in milliseconds")
    verify_mean_ms: float = Field(..., description="Verify time in milliseconds")
    
    # Gas and storage metrics
    estimated_evm_calldata_gas: int = Field(..., description="Estimated EVM calldata gas cost")
    estimated_evm_storage_slots: int = Field(..., description="Estimated 32-byte storage slots needed")
    size_overhead_vs_ecdsa_factor: float = Field(..., description="Signature size multiplier vs ECDSA secp256k1")


class BenchmarkSuiteResult(BaseModel):
    timestamp_utc: str = Field(..., description="Benchmark execution timestamp")
    iterations_per_algo: int = Field(..., description="Iterations run per algorithm")
    message_sizes_tested: List[int] = Field(default_factory=list)
    system_info: Dict[str, str] = Field(default_factory=dict)
    algorithms: List[AlgorithmBenchmarkMetrics] = Field(default_factory=list)


class GasEstimateComparison(BaseModel):
    algorithm: str
    signature_bytes: int
    public_key_bytes: int
    calldata_gas_cost: int
    storage_slots_32b: int
    storage_gas_sstore_new: int
    storage_gas_sstore_update: int
    cost_multiplier_vs_ecdsa: float
    l1_tx_cost_usd_at_30gwei: float


class PQCRecommendation(BaseModel):
    recommended_algorithm: str = Field(..., description="Recommended algorithm code")
    algorithm_name: str = Field(..., description="Recommended algorithm full name")
    use_case: str = Field(..., description="Target use case (e.g. general_wallet, on_chain_zk, high_security_vault)")
    rationale: str = Field(..., description="Explanation of why this algorithm is recommended")
    tradeoffs: Dict[str, str] = Field(default_factory=dict, description="Key trade-offs (e.g. speed vs size)")
    nist_fips_status: str = Field(..., description="NIST standardization status")


class SignedReport(BaseModel):
    canonical_report_hash_sha256: str = Field(..., description="SHA-256 of canonical report JSON")
    canonical_report_hash_keccak256: str = Field(..., description="Keccak-256 of canonical report JSON")
    signing_algorithm: str = Field(default="ML-DSA-44", description="PQC algorithm used to sign report")
    signer_public_key_hex: str = Field(..., description="Public key of the reporting authority")
    pqc_signature_hex: str = Field(..., description="ML-DSA digital signature of the canonical report hash")
    verification_status: str = Field(..., description="VERIFIED or TAMPERED")
    timestamp_utc: str = Field(...)

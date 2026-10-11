"""
PQC Recommendation Engine and Quantum Risk Scoring Module.
Provides rule-based recommendation mapping and risk scoring formulas:
risk = algorithm_weight * exposure * signature_lifetime * confidence.
"""

from typing import Dict, List, Optional
from schemas.crypto_schemas import PQCRecommendation


# Algorithm Quantum Vulnerability Weights
ALGORITHM_QUANTUM_WEIGHTS = {
    # Classical Schemes (Polynomial-time break via Shor's Algorithm)
    "secp256k1": 1.0,
    "ecdsa": 1.0,
    "rsa": 1.0,
    "ed25519": 1.0,
    "ecrecover": 1.0,
    "bitcoinjs": 1.0,
    "ethers.wallet": 1.0,
    
    # Post-Quantum Schemes
    "falcon-512": 0.25,
    "falcon-1024": 0.20,
    "ml-dsa-44": 0.15,
    "ml-dsa-65": 0.10,
    "ml-dsa-87": 0.05,
    "slh-dsa-shake-128f": 0.08,
    "slh-dsa-shake-128s": 0.08,
    "slh-dsa-shake-256f": 0.03,
    "hybrid_ecdsa_ml_dsa_44": 0.10,
    "hybrid_ecdsa_ml_dsa_65": 0.08,
}


USE_CASE_RECOMMENDATIONS = {
    "gas_constrained_evm": PQCRecommendation(
        recommended_algorithm="Falcon-512",
        algorithm_name="Falcon-512 (FN-DSA / NTRU Lattice)",
        use_case="On-Chain Smart Contracts & Gas-Constrained Blockchains",
        rationale=(
            "Falcon-512 produces the smallest combined public key and signature size (666 bytes signature, "
            "897 bytes public key) among all NIST PQC candidates. This minimizes EVM calldata gas consumption "
            "to ~10,656 gas, saving over 72% in on-chain transaction costs compared to ML-DSA-44."
        ),
        tradeoffs={
            "advantage": "Lowest calldata gas cost (666 B), fastest signature verification.",
            "disadvantage": "Requires complex floating-point / Fast Fourier arithmetic during signing.",
        },
        nist_fips_status="NIST Selected Round 3 (Draft FN-DSA standardization in progress)",
    ),
    "balanced_general_wallet": PQCRecommendation(
        recommended_algorithm="ML-DSA-44",
        algorithm_name="ML-DSA-44 (FIPS 204 / Dilithium2)",
        use_case="General Purpose dApps, Web3 Wallets & Account Abstraction",
        rationale=(
            "NIST's primary standardized general-purpose signature algorithm (FIPS 204). Offers balanced "
            "performance, extremely fast verification (sub-millisecond), constant-time arithmetic without "
            "floating point dependencies, and 128-bit quantum security level (NIST Level 2)."
        ),
        tradeoffs={
            "advantage": "NIST FIPS 204 standardized, simple integer polynomial arithmetic, fast signing.",
            "disadvantage": "Signature size is 2,420 bytes (~38,720 EVM calldata gas).",
        },
        nist_fips_status="NIST FIPS 204 Final Standard (August 2024)",
    ),
    "high_security_treasury": PQCRecommendation(
        recommended_algorithm="SLH-DSA-SHAKE-256f",
        algorithm_name="SLH-DSA-SHAKE-256f (FIPS 205 / SPHINCS+ Level 5)",
        use_case="Long-Term Cold Storage, DAO Treasuries & Sovereign Governance",
        rationale=(
            "Stateless hash-based signature standard (FIPS 205). Makes zero hardness assumptions on lattice "
            "problems; its security relies strictly on the pre-image and collision resistance of SHAKE-256 / SHA-3. "
            "Guarantees maximum conservative post-quantum security against any future lattice cryptanalysis."
        ),
        tradeoffs={
            "advantage": "Highest conservative security (NIST Level 5), zero lattice assumptions.",
            "disadvantage": "Large signature footprint (49,856 bytes), slower keygen/sign times.",
        },
        nist_fips_status="NIST FIPS 205 Final Standard (August 2024)",
    ),
    "hybrid_migration_transition": PQCRecommendation(
        recommended_algorithm="Hybrid_ECDSA_ML_DSA_44",
        algorithm_name="Hybrid (ECDSA secp256k1 + ML-DSA-44)",
        use_case="Immediate Production Migration with Backwards EVM Compatibility",
        rationale=(
            "Dual-signing scheme combining classical ECDSA (secp256k1) with ML-DSA-44. Provides immediate "
            "compatibility with legacy Ethereum consensus and ecrecover verification, while simultaneously "
            "attaching an immutable quantum-safe cryptographic proof."
        ),
        tradeoffs={
            "advantage": "Full backwards compatibility with legacy nodes + quantum future-proofing.",
            "disadvantage": "Combined signature size of 2,484 bytes.",
        },
        nist_fips_status="Dual Standard (FIPS 186-5 + FIPS 204 composite)",
    ),
}


def calculate_quantum_risk(
    algorithm_name: str,
    exposure_factor: float = 1.0,
    signature_lifetime_years: float = 5.0,
    confidence: float = 0.95,
) -> Dict:
    """
    Calculate quantum risk score using the formula:
    risk = algorithm_weight * exposure * signature_lifetime * confidence.
    """
    normalized_algo = algorithm_name.lower().replace("_", "-").replace(" ", "")
    weight = 1.0
    for key, val in ALGORITHM_QUANTUM_WEIGHTS.items():
        if key in normalized_algo:
            weight = val
            break

    # Normalize lifetime factor (e.g. 5+ years increases risk due to 'harvest now, decrypt/forge later')
    lifetime_multiplier = min(max(signature_lifetime_years / 5.0, 0.2), 3.0)
    
    raw_risk = weight * exposure_factor * lifetime_multiplier * confidence
    # Scale to 0 - 100 index
    risk_index = round(min(raw_risk * 25.0, 100.0), 2)

    if risk_index >= 70.0:
        severity = "CRITICAL"
        urgency = "Immediate Migration Required"
    elif risk_index >= 40.0:
        severity = "HIGH"
        urgency = "Migrate in Next Release Cycle"
    elif risk_index >= 20.0:
        severity = "MEDIUM"
        urgency = "Plan Migration Strategy"
    else:
        severity = "LOW"
        urgency = "Quantum Safe / Low Exposure"

    return {
        "algorithm": algorithm_name,
        "algorithm_quantum_weight": weight,
        "exposure_factor": exposure_factor,
        "signature_lifetime_years": signature_lifetime_years,
        "confidence": confidence,
        "risk_index": risk_index,
        "severity": severity,
        "migration_urgency": urgency,
    }


def get_recommendation_for_use_case(use_case_key: str) -> PQCRecommendation:
    """Lookup recommended PQC algorithm for a given use case profile."""
    if use_case_key in USE_CASE_RECOMMENDATIONS:
        return USE_CASE_RECOMMENDATIONS[use_case_key]
    return USE_CASE_RECOMMENDATIONS["balanced_general_wallet"]


def get_all_recommendations() -> Dict[str, PQCRecommendation]:
    """Retrieve all recommendation profiles."""
    return USE_CASE_RECOMMENDATIONS

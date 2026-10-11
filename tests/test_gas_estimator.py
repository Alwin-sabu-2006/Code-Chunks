"""
Unit Tests for EVM Gas Estimator and Recommendation Engine.
"""

import pytest
from crypto.gas_estimator import EVMGasEstimator
from crypto.recommendation import calculate_quantum_risk, get_recommendation_for_use_case
from schemas.crypto_schemas import GasEstimateComparison


def test_gas_estimator_ecdsa_vs_falcon():
    estimator = EVMGasEstimator(eth_price_usd=3000.0, gas_price_gwei=30.0)
    ecdsa_est = estimator.estimate_algorithm_gas("ECDSA_secp256k1")
    falcon_est = estimator.estimate_algorithm_gas("Falcon-512")
    mldsa_est = estimator.estimate_algorithm_gas("ML-DSA-44")

    assert ecdsa_est.calldata_gas_cost == 64 * 16
    assert ecdsa_est.storage_slots_32b == 2

    assert falcon_est.signature_bytes == 666
    assert falcon_est.calldata_gas_cost == 666 * 16

    assert mldsa_est.signature_bytes == 2420
    assert mldsa_est.calldata_gas_cost == 2420 * 16
    assert mldsa_est.calldata_gas_cost > falcon_est.calldata_gas_cost


def test_quantum_risk_scoring():
    # Classical should have high risk
    res_ecdsa = calculate_quantum_risk("secp256k1", exposure_factor=1.0, signature_lifetime_years=10.0)
    assert res_ecdsa["severity"] in ["CRITICAL", "HIGH"]
    assert res_ecdsa["risk_index"] > 40.0

    # PQC should have low risk
    res_pqc = calculate_quantum_risk("ML-DSA-44", exposure_factor=1.0, signature_lifetime_years=10.0)
    assert res_pqc["risk_index"] < res_ecdsa["risk_index"]


def test_recommendation_profiles():
    rec_evm = get_recommendation_for_use_case("gas_constrained_evm")
    assert rec_evm.recommended_algorithm == "Falcon-512"

    rec_general = get_recommendation_for_use_case("balanced_general_wallet")
    assert rec_general.recommended_algorithm == "ML-DSA-44"

    rec_sec = get_recommendation_for_use_case("high_security_treasury")
    assert "SLH-DSA" in rec_sec.recommended_algorithm

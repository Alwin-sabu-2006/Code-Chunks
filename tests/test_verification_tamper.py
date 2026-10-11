"""
Unit Tests for 4-Scenario PQC Tamper Verification Suite.
"""

import pytest
from crypto.verification import PQCTamperVerifier, flip_bit
from crypto.registry import CryptoRegistry
from schemas.crypto_schemas import VerificationMatrix


def test_flip_bit_utility():
    orig = b"HELLO_WORLD_1234"
    flipped = flip_bit(orig, byte_index=3, bit_index=2)
    assert flipped != orig
    assert len(flipped) == len(orig)
    # Double flip reverts
    reverted = flip_bit(flipped, byte_index=3, bit_index=2)
    assert reverted == orig


@pytest.mark.parametrize("algo_id", CryptoRegistry.list_algorithms())
def test_algorithm_tamper_matrix(algo_id: str):
    verifier = PQCTamperVerifier()
    signer = CryptoRegistry.get_signer(algo_id)
    res = verifier.test_algorithm(signer)

    assert res.all_tests_passed is True
    assert res.tamper_detection_rate_pct == 100.0
    assert len(res.scenarios) == 4

    scenarios = {s.scenario_name: s for s in res.scenarios}
    assert scenarios["valid_signature"].passed_test is True
    assert scenarios["tampered_message"].passed_test is True
    assert scenarios["tampered_signature"].passed_test is True
    assert scenarios["wrong_public_key"].passed_test is True


def test_full_matrix():
    verifier = PQCTamperVerifier()
    matrix = verifier.run_full_matrix()
    assert isinstance(matrix, VerificationMatrix)
    assert matrix.overall_tamper_detection_rate_pct == 100.0
    assert len(matrix.results) == len(CryptoRegistry.list_algorithms())

"""
Unit Tests for PQC Benchmark Harness.
"""

import pytest
from crypto.benchmark import PQCBenchmarkHarness
from crypto.registry import CryptoRegistry
from schemas.crypto_schemas import BenchmarkSuiteResult, AlgorithmBenchmarkMetrics


def test_single_algorithm_benchmark():
    harness = PQCBenchmarkHarness(warmup_iterations=2, iterations=10)
    signer = CryptoRegistry.get_signer("ML-DSA-44")
    metric = harness.benchmark_algorithm(signer)

    assert isinstance(metric, AlgorithmBenchmarkMetrics)
    assert metric.algorithm == "ML-DSA-44"
    assert metric.iterations == 10
    assert metric.keygen_mean_ns > 0
    assert metric.sign_mean_ns > 0
    assert metric.verify_mean_ns > 0
    assert metric.public_key_bytes == 1312
    assert metric.signature_bytes == 2420
    assert metric.estimated_evm_calldata_gas == 2420 * 16


def test_full_suite_benchmark():
    harness = PQCBenchmarkHarness(warmup_iterations=2, iterations=5)
    suite = harness.run_full_suite(algorithm_ids=["ECDSA_secp256k1", "ML-DSA-44", "Falcon-512"])

    assert isinstance(suite, BenchmarkSuiteResult)
    assert len(suite.algorithms) == 3
    assert "system_info" in suite.model_dump()
    assert suite.algorithms[0].algorithm == "ECDSA_secp256k1"
    assert suite.algorithms[1].algorithm == "ML-DSA-44"
    assert suite.algorithms[2].algorithm == "Falcon-512"

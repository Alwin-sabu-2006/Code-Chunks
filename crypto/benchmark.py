"""
PQC Benchmark Harness.
Measures high-precision timings (ns) for keygen, sign, and verify across
100+ iterations with warmup, computing statistical mean, standard deviation,
size footprints, and EVM gas overheads.
"""

import time
import math
import platform
import statistics
from datetime import datetime, timezone
from typing import List, Dict, Optional

from crypto.registry import CryptoRegistry
from crypto.base import CryptoSigner
from schemas.crypto_schemas import (
    AlgorithmBenchmarkMetrics,
    BenchmarkSuiteResult,
)


class PQCBenchmarkHarness:
    """Benchmark harness executing high-precision timing and size measurements."""

    def __init__(self, warmup_iterations: int = 5, iterations: int = 100):
        self.warmup_iterations = warmup_iterations
        self.iterations = iterations

    def benchmark_algorithm(
        self, signer: CryptoSigner, message: bytes = b"Q-Chain: Post-Quantum Security Assessment Payload 2026"
    ) -> AlgorithmBenchmarkMetrics:
        """Benchmark a single cryptographic signer."""
        # 1. Warm-up
        for _ in range(self.warmup_iterations):
            pk_w, sk_w = signer.keygen()
            sig_w = signer.sign(message, sk_w)
            _ = signer.verify(message, sig_w, pk_w)

        # 2. Keygen Benchmarks
        keygen_times_ns: List[int] = []
        keypairs = []
        for _ in range(self.iterations):
            t0 = time.perf_counter_ns()
            pk, sk = signer.keygen()
            t1 = time.perf_counter_ns()
            keygen_times_ns.append(t1 - t0)
            keypairs.append((pk, sk))

        # Sample representative keypair for sizes
        sample_pk, sample_sk = keypairs[0]

        # 3. Sign Benchmarks
        sign_times_ns: List[int] = []
        signatures = []
        for pk, sk in keypairs:
            t0 = time.perf_counter_ns()
            sig = signer.sign(message, sk)
            t1 = time.perf_counter_ns()
            sign_times_ns.append(t1 - t0)
            signatures.append(sig)

        sample_sig = signatures[0]

        # 4. Verify Benchmarks
        verify_times_ns: List[int] = []
        for (pk, sk), sig in zip(keypairs, signatures):
            t0 = time.perf_counter_ns()
            valid = signer.verify(message, sig, pk)
            t1 = time.perf_counter_ns()
            verify_times_ns.append(t1 - t0)
            if not valid:
                raise RuntimeError(f"Verification failed during benchmark of {signer.algorithm_id}")

        # Compute statistics
        kg_mean = statistics.mean(keygen_times_ns)
        kg_std = statistics.stdev(keygen_times_ns) if len(keygen_times_ns) > 1 else 0.0

        sign_mean = statistics.mean(sign_times_ns)
        sign_std = statistics.stdev(sign_times_ns) if len(sign_times_ns) > 1 else 0.0

        ver_mean = statistics.mean(verify_times_ns)
        ver_std = statistics.stdev(verify_times_ns) if len(verify_times_ns) > 1 else 0.0

        # Calculate EVM Calldata Gas:
        # 16 gas per non-zero byte, 4 gas per zero byte in Ethereum EIP-2028
        # We assume typical non-zero cryptographic randomness (~15.9 gas/byte average)
        calldata_gas = int(len(sample_sig) * 16)
        # Storage slots: 32 bytes per slot
        storage_slots = math.ceil(len(sample_sig) / 32)

        # Baseline comparison vs ECDSA 64 bytes
        size_overhead = round(len(sample_sig) / 64.0, 2)

        return AlgorithmBenchmarkMetrics(
            algorithm=signer.algorithm_id,
            display_name=signer.display_name,
            category=signer.category,
            standard=signer.standard,
            nist_level=signer.nist_level,
            public_key_bytes=len(sample_pk),
            private_key_bytes=len(sample_sk),
            signature_bytes=len(sample_sig),
            message_bytes=len(message),
            iterations=self.iterations,
            keygen_mean_ns=kg_mean,
            keygen_std_dev_ns=kg_std,
            sign_mean_ns=sign_mean,
            sign_std_dev_ns=sign_std,
            verify_mean_ns=ver_mean,
            verify_std_dev_ns=ver_std,
            keygen_mean_ms=round(kg_mean / 1_000_000.0, 4),
            sign_mean_ms=round(sign_mean / 1_000_000.0, 4),
            verify_mean_ms=round(ver_mean / 1_000_000.0, 4),
            estimated_evm_calldata_gas=calldata_gas,
            estimated_evm_storage_slots=storage_slots,
            size_overhead_vs_ecdsa_factor=size_overhead,
        )

    def run_full_suite(
        self,
        algorithm_ids: Optional[List[str]] = None,
        message: bytes = b"Q-Chain: Post-Quantum Security Assessment Payload 2026",
    ) -> BenchmarkSuiteResult:
        """Run benchmark suite across all or specified algorithms."""
        if algorithm_ids is None:
            signers = CryptoRegistry.get_all_signers()
        else:
            signers = [CryptoRegistry.get_signer(aid) for aid in algorithm_ids]

        results: List[AlgorithmBenchmarkMetrics] = []
        for signer in signers:
            metric = self.benchmark_algorithm(signer, message=message)
            results.append(metric)

        sys_info = {
            "os": platform.system(),
            "os_release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
        }

        return BenchmarkSuiteResult(
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            iterations_per_algo=self.iterations,
            message_sizes_tested=[len(message)],
            system_info=sys_info,
            algorithms=results,
        )

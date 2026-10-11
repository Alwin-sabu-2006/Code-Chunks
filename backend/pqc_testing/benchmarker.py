"""
Performance Benchmarking Harness for Post-Quantum vs Classical Signatures.
Measures real hardware execution times with statistics (mean, stddev, min, max)
and calculates blockchain on-chain storage/gas implications.
Part of Q-Chain Platform (Member 2 Deliverable).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import math
import os
import platform
import sys
import time

from .base import (
    BaseSignatureScheme,
    KeyPair,
    ParameterSetId,
    SignatureResult,
    VerificationOutcome,
    ALGORITHM_CATALOG,
)
from .mldsa_signer import MLDSASigner
from .ecdsa_signer import ECDSABaselineSigner


@dataclass
class TimingStats:
    unit: str  # e.g., "milliseconds"
    mean: float
    stddev: float
    min_val: float
    max_val: float
    trials: int
    raw_measurements: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "unit": self.unit,
            "mean_ms": round(self.mean, 4),
            "stddev_ms": round(self.stddev, 4),
            "min_ms": round(self.min_val, 4),
            "max_ms": round(self.max_val, 4),
            "trials": self.trials,
        }


@dataclass
class OnChainCostEstimate:
    """Estimates on-chain transaction footprint and gas cost (Ethereum EVM)."""
    public_key_bytes: int
    signature_bytes: int
    total_crypto_bytes: int
    calldata_gas_estimate: int  # Standard ~16 gas per byte for non-zero calldata
    storage_slots_required: int  # 32 bytes per EVM storage slot (SSTORE)
    relative_overhead_vs_ecdsa: float  # e.g., 25x larger than ECDSA

    def to_dict(self) -> Dict[str, Any]:
        return {
            "public_key_bytes": self.public_key_bytes,
            "signature_bytes": self.signature_bytes,
            "total_crypto_bytes": self.total_crypto_bytes,
            "calldata_gas_estimate": self.calldata_gas_estimate,
            "storage_slots_required": self.storage_slots_required,
            "relative_overhead_vs_ecdsa": round(self.relative_overhead_vs_ecdsa, 2),
        }


@dataclass
class BenchmarkReport:
    algorithm_id: str
    algorithm_name: str
    standard: str
    family: str
    quantum_safe: bool
    trials: int
    keygen_stats: TimingStats
    sign_stats: TimingStats
    verify_stats: TimingStats
    public_key_size_bytes: int
    private_key_size_bytes: int
    signature_size_bytes: int
    on_chain_costs: OnChainCostEstimate
    environment: Dict[str, str]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm_id": self.algorithm_id,
            "algorithm_name": self.algorithm_name,
            "standard": self.standard,
            "family": self.family,
            "quantum_safe": self.quantum_safe,
            "trials": self.trials,
            "public_key_size_bytes": self.public_key_size_bytes,
            "private_key_size_bytes": self.private_key_size_bytes,
            "signature_size_bytes": self.signature_size_bytes,
            "keygen_timing": self.keygen_stats.to_dict(),
            "sign_timing": self.sign_stats.to_dict(),
            "verify_timing": self.verify_stats.to_dict(),
            "on_chain_costs": self.on_chain_costs.to_dict(),
            "environment": self.environment,
            "timestamp": self.timestamp,
        }


class PQCBenchmarker:
    """
    Precision benchmarking harness for PQC and classical signature schemes.
    Does NOT fabricate results: executes live cryptographic rounds on local hardware.
    """

    def __init__(self):
        self._environment_info = {
            "os": f"{platform.system()} {platform.release()} ({platform.version()})",
            "python_version": sys.version.split()[0],
            "architecture": platform.machine(),
            "processor": platform.processor() or "x86_64",
            "measurement_timer": "time.perf_counter_ns",
        }

    @staticmethod
    def _calculate_stats(measurements_ms: List[float]) -> TimingStats:
        n = len(measurements_ms)
        if n == 0:
            return TimingStats(unit="milliseconds", mean=0.0, stddev=0.0, min_val=0.0, max_val=0.0, trials=0)

        mean_val = sum(measurements_ms) / n
        if n > 1:
            variance = sum((x - mean_val) ** 2 for x in measurements_ms) / (n - 1)
            stddev = math.sqrt(variance)
        else:
            stddev = 0.0

        return TimingStats(
            unit="milliseconds",
            mean=mean_val,
            stddev=stddev,
            min_val=min(measurements_ms),
            max_val=max(measurements_ms),
            trials=n,
            raw_measurements=measurements_ms,
        )

    def benchmark_scheme(
        self,
        signer: BaseSignatureScheme,
        trials: int = 20,
        warmup_runs: int = 2,
        sample_payload: bytes = b"Q-CHAIN: POST-QUANTUM MIGRATION BENCHMARK TEST TRANSACTION DATA",
    ) -> BenchmarkReport:
        """
        Runs rigorous timing benchmarks across keygen, sign, and verify phases.
        """
        if trials < 1:
            raise ValueError("trials must be >= 1")

        # Warmup phase (to stabilize JIT / caches)
        for _ in range(warmup_runs):
            kp_warm = signer.generate_keypair()
            sig_warm = signer.sign(kp_warm.private_key, sample_payload)
            signer.verify(kp_warm.public_key, sample_payload, sig_warm.signature)

        keygen_times_ms: List[float] = []
        sign_times_ms: List[float] = []
        verify_times_ms: List[float] = []

        last_kp: Optional[KeyPair] = None
        last_sig: Optional[SignatureResult] = None

        for _ in range(trials):
            # Key generation benchmark
            t0 = time.perf_counter_ns()
            kp = signer.generate_keypair()
            t1 = time.perf_counter_ns()
            keygen_times_ms.append((t1 - t0) / 1_000_000.0)
            last_kp = kp

            # Signing benchmark
            t0 = time.perf_counter_ns()
            sig = signer.sign(kp.private_key, sample_payload)
            t1 = time.perf_counter_ns()
            sign_times_ms.append((t1 - t0) / 1_000_000.0)
            last_sig = sig

            # Verification benchmark
            t0 = time.perf_counter_ns()
            v_res = signer.verify(kp.public_key, sample_payload, sig.signature)
            t1 = time.perf_counter_ns()
            verify_times_ms.append((t1 - t0) / 1_000_000.0)

            if not v_res.valid:
                raise RuntimeError(f"Verification unexpectedly failed during benchmarking of {signer.algorithm}")

        assert last_kp is not None and last_sig is not None

        pk_size = len(last_kp.public_key)
        sk_size = len(last_kp.private_key)
        sig_size = len(last_sig.signature)

        # Baseline ECDSA secp256k1 size is 65-byte PK + 64-byte signature = 129 bytes
        ecdsa_total_bytes = 129
        current_total_bytes = pk_size + sig_size
        relative_overhead = current_total_bytes / float(ecdsa_total_bytes)

        # Gas estimate: ~16 gas per calldata byte in EVM
        calldata_gas = current_total_bytes * 16
        storage_slots = math.ceil(current_total_bytes / 32)

        meta = ALGORITHM_CATALOG.get(signer.algorithm)
        algo_name = meta.name if meta else signer.algorithm.value
        standard = meta.standard if meta else "Custom"
        family = meta.family.value if meta else "Unknown"
        quantum_safe = meta.quantum_safe if meta else False

        cost_est = OnChainCostEstimate(
            public_key_bytes=pk_size,
            signature_bytes=sig_size,
            total_crypto_bytes=current_total_bytes,
            calldata_gas_estimate=calldata_gas,
            storage_slots_required=storage_slots,
            relative_overhead_vs_ecdsa=relative_overhead,
        )

        return BenchmarkReport(
            algorithm_id=signer.algorithm.value,
            algorithm_name=algo_name,
            standard=standard,
            family=family,
            quantum_safe=quantum_safe,
            trials=trials,
            keygen_stats=self._calculate_stats(keygen_times_ms),
            sign_stats=self._calculate_stats(sign_times_ms),
            verify_stats=self._calculate_stats(verify_times_ms),
            public_key_size_bytes=pk_size,
            private_key_size_bytes=sk_size,
            signature_size_bytes=sig_size,
            on_chain_costs=cost_est,
            environment=self._environment_info,
        )

    def run_comparative_benchmark(
        self,
        trials: int = 10,
        include_all_mldsa_levels: bool = True,
    ) -> Dict[str, Any]:
        """
        Runs comprehensive comparative benchmark across ECDSA baseline and ML-DSA schemes.
        """
        signers: List[BaseSignatureScheme] = [
            ECDSABaselineSigner(),
            MLDSASigner(ParameterSetId.ML_DSA_44),
        ]
        if include_all_mldsa_levels:
            signers.append(MLDSASigner(ParameterSetId.ML_DSA_65))
            signers.append(MLDSASigner(ParameterSetId.ML_DSA_87))

        reports = []
        for s in signers:
            rep = self.benchmark_scheme(s, trials=trials)
            reports.append(rep)

        return {
            "comparison_summary": [r.to_dict() for r in reports],
            "trials_per_algorithm": trials,
            "environment": self._environment_info,
            "timestamp": time.time(),
        }

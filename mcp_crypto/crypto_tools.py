"""
MCP Tool Implementations for Cryptography & PQC Benchmarking.
Directly consumable by Member 3 (Backend & MCP Engineer) for MCP servers.
"""

import json
import time
from typing import Dict, List, Optional, Any
from crypto.registry import CryptoRegistry
from crypto.benchmark import PQCBenchmarkHarness
from crypto.verification import PQCTamperVerifier
from crypto.gas_estimator import EVMGasEstimator
from crypto.recommendation import get_recommendation_for_use_case, calculate_quantum_risk
from crypto.report_signer import PQCReportSigner, compute_report_hashes, canonicalize_json


def tool_crypto_list_algorithms() -> Dict[str, Any]:
    """
    List all supported classical and post-quantum signing algorithms and their properties.
    """
    return {
        "algorithms": CryptoRegistry.get_summary_table(),
    }


def tool_crypto_generate_keypair(algorithm: str) -> Dict[str, Any]:
    """
    Generate a public/private keypair for the specified algorithm.
    """
    signer = CryptoRegistry.get_signer(algorithm)
    pk, sk = signer.keygen()
    return {
        "algorithm": signer.algorithm_id,
        "display_name": signer.display_name,
        "standard": signer.standard,
        "public_key_hex": pk.hex(),
        "private_key_hex": sk.hex(),
        "public_key_bytes_len": len(pk),
        "private_key_bytes_len": len(sk),
    }


def tool_crypto_sign_message(algorithm: str, message_hex: str, private_key_hex: str) -> Dict[str, Any]:
    """
    Sign a message using the specified algorithm and private key.
    """
    signer = CryptoRegistry.get_signer(algorithm)
    msg_bytes = bytes.fromhex(message_hex)
    sk_bytes = bytes.fromhex(private_key_hex)
    
    t0 = time.perf_counter_ns()
    signature = signer.sign(msg_bytes, sk_bytes)
    t1 = time.perf_counter_ns()
    
    return {
        "algorithm": signer.algorithm_id,
        "message_hex": message_hex,
        "signature_hex": signature.hex(),
        "signature_bytes_len": len(signature),
        "sign_time_ns": t1 - t0,
        "sign_time_ms": round((t1 - t0) / 1_000_000.0, 4),
    }


def tool_crypto_verify_signature(
    algorithm: str, message_hex: str, signature_hex: str, public_key_hex: str
) -> Dict[str, Any]:
    """
    Verify a signature against message and public key.
    """
    signer = CryptoRegistry.get_signer(algorithm)
    msg_bytes = bytes.fromhex(message_hex)
    sig_bytes = bytes.fromhex(signature_hex)
    pk_bytes = bytes.fromhex(public_key_hex)

    t0 = time.perf_counter_ns()
    is_valid = signer.verify(msg_bytes, sig_bytes, pk_bytes)
    t1 = time.perf_counter_ns()

    return {
        "algorithm": signer.algorithm_id,
        "is_valid": is_valid,
        "verify_time_ns": t1 - t0,
        "verify_time_ms": round((t1 - t0) / 1_000_000.0, 4),
    }


def tool_crypto_run_tamper_matrix(algorithm_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Execute the 4-scenario tamper verification suite (valid, flipped msg bit, flipped sig bit, wrong key).
    """
    verifier = PQCTamperVerifier()
    matrix = verifier.run_full_matrix(algorithm_ids=algorithm_ids)
    return matrix.model_dump()


def tool_crypto_run_benchmark(
    algorithm_ids: Optional[List[str]] = None,
    iterations: int = 100,
    message_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute statistical benchmark harness across algorithms measuring keygen, sign, verify timings & variance.
    """
    msg = bytes.fromhex(message_hex) if message_hex else b"Q-Chain: Post-Quantum Security Assessment Payload 2026"
    harness = PQCBenchmarkHarness(iterations=iterations)
    result = harness.run_full_suite(algorithm_ids=algorithm_ids, message=msg)
    return result.model_dump()


def tool_crypto_estimate_gas_costs(
    eth_price_usd: float = 3000.0, gas_price_gwei: float = 30.0
) -> Dict[str, Any]:
    """
    Estimate EVM calldata gas and storage slot costs comparing ECDSA to all PQC algorithms.
    """
    estimator = EVMGasEstimator(eth_price_usd=eth_price_usd, gas_price_gwei=gas_price_gwei)
    return estimator.get_breakdown_dict()


def tool_crypto_sign_report(report_json_str: str, algorithm: str = "ML-DSA-44") -> Dict[str, Any]:
    """
    Compute canonical hash of JSON report and sign with ML-DSA digital signature.
    """
    report_dict = json.loads(report_json_str)
    signer = PQCReportSigner(variant=algorithm)
    signed = signer.sign_report(report_dict)
    return signed.model_dump()


def tool_crypto_get_recommendation(use_case: str) -> Dict[str, Any]:
    """
    Retrieve recommended PQC algorithm and architectural rationale for a specific blockchain use case.
    """
    rec = get_recommendation_for_use_case(use_case)
    return rec.model_dump()

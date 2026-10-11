"""
FastAPI REST API Router for Post-Quantum Cryptography Signature Testing Module.
Exposes clean endpoints for key generation, signing, verification, tamper-testing,
and performance benchmarking.
Part of Q-Chain Platform (Member 2 Deliverable).
"""

from typing import Any, Dict, List, Optional
import base64
import binascii

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from .base import (
    ALGORITHM_CATALOG,
    BaseSignatureScheme,
    KeyPair,
    ParameterSetId,
)
from .mldsa_signer import MLDSASigner
from .ecdsa_signer import ECDSABaselineSigner
from .tamper_tester import TamperTester
from .benchmarker import PQCBenchmarker


router = APIRouter(prefix="/api/pqc", tags=["Post-Quantum Cryptography Signature Testing"])


def get_signer_instance(algo_name: str) -> BaseSignatureScheme:
    """Helper to instantiate appropriate signer based on algorithm identifier."""
    algo_clean = algo_name.strip()
    try:
        pid = ParameterSetId(algo_clean)
    except ValueError:
        valid_ids = [p.value for p in ParameterSetId]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported algorithm '{algo_name}'. Supported algorithms: {valid_ids}",
        )

    if pid == ParameterSetId.ECDSA_SECP256K1:
        return ECDSABaselineSigner()
    else:
        return MLDSASigner(parameter_set=pid)


# ==========================================
# Pydantic Request & Response Schemas
# ==========================================

class AlgorithmInfoResponse(BaseModel):
    id: str
    name: str
    standard: str
    family: str
    nist_security_level: int
    quantum_safe: bool
    claimed_security: str
    description: str


class KeyGenRequest(BaseModel):
    algorithm: str = Field(default=ParameterSetId.ML_DSA_44.value, description="ML-DSA-44, ML-DSA-65, ML-DSA-87, or ECDSA-secp256k1")
    include_private_key: bool = Field(default=True, description="Whether to include private key in response")


class KeyGenResponse(BaseModel):
    algorithm: str
    public_key_hex: str
    public_key_b64: str
    public_key_size_bytes: int
    private_key_size_bytes: int
    private_key_hex: Optional[str] = None
    private_key_b64: Optional[str] = None
    duration_ms: float


class SignRequest(BaseModel):
    algorithm: str = Field(default=ParameterSetId.ML_DSA_44.value)
    private_key_hex: str = Field(description="Hex-encoded private key")
    message: str = Field(description="Plain text or hex payload to sign")
    is_message_hex: bool = Field(default=False, description="If true, message string is decoded as hex bytes")


class SignResponse(BaseModel):
    algorithm: str
    signature_hex: str
    signature_b64: str
    signature_size_bytes: int
    duration_ms: float
    message_digest_preview: str


class VerifyRequest(BaseModel):
    algorithm: str = Field(default=ParameterSetId.ML_DSA_44.value)
    public_key_hex: str = Field(description="Hex-encoded public key")
    signature_hex: str = Field(description="Hex-encoded signature")
    message: str = Field(description="Original message string or hex")
    is_message_hex: bool = Field(default=False)


class VerifyResponse(BaseModel):
    algorithm: str
    valid: bool
    duration_ms: float
    error_message: Optional[str] = None


class TamperTestRequest(BaseModel):
    algorithm: str = Field(default=ParameterSetId.ML_DSA_44.value)
    custom_message: Optional[str] = Field(default=None, description="Optional custom payload for tamper testing")


class BenchmarkRequest(BaseModel):
    algorithm: Optional[str] = Field(default=ParameterSetId.ML_DSA_44.value, description="If null or 'all', benchmarks all schemes")
    trials: int = Field(default=10, ge=1, le=100, description="Number of execution rounds")
    compare_against_ecdsa: bool = Field(default=True, description="Include ECDSA secp256k1 baseline in comparison")


# ==========================================
# Endpoints
# ==========================================

@router.get("/algorithms", response_model=List[AlgorithmInfoResponse])
def list_algorithms():
    """
    List all supported post-quantum digital signature algorithms and classical baseline.
    """
    return [
        AlgorithmInfoResponse(
            id=meta.id.value,
            name=meta.name,
            standard=meta.standard,
            family=meta.family.value,
            nist_security_level=meta.nist_security_level,
            quantum_safe=meta.quantum_safe,
            claimed_security=meta.claimed_security,
            description=meta.description,
        )
        for meta in ALGORITHM_CATALOG.values()
    ]


@router.post("/keygen", response_model=KeyGenResponse)
def generate_keypair(payload: KeyGenRequest):
    """
    Generate public and private keypairs for ML-DSA or classical baseline.
    """
    signer = get_signer_instance(payload.algorithm)
    import time
    t0 = time.perf_counter_ns()
    kp = signer.generate_keypair()
    t1 = time.perf_counter_ns()
    duration_ms = (t1 - t0) / 1_000_000.0

    return KeyGenResponse(
        algorithm=kp.algorithm.value,
        public_key_hex=kp.public_key_hex,
        public_key_b64=kp.public_key_b64,
        public_key_size_bytes=kp.public_key_size,
        private_key_size_bytes=kp.private_key_size,
        private_key_hex=kp.private_key.hex() if payload.include_private_key else None,
        private_key_b64=base64.b64encode(kp.private_key).decode("utf-8") if payload.include_private_key else None,
        duration_ms=round(duration_ms, 4),
    )


@router.post("/sign", response_model=SignResponse)
def sign_message(payload: SignRequest):
    """
    Sign a sample message or transaction payload using ML-DSA or ECDSA private key.
    """
    signer = get_signer_instance(payload.algorithm)

    try:
        sk_bytes = bytes.fromhex(payload.private_key_hex.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex string for private_key_hex")

    if payload.is_message_hex:
        try:
            msg_bytes = bytes.fromhex(payload.message.strip())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid hex string for message")
    else:
        msg_bytes = payload.message.encode("utf-8")

    try:
        res = signer.sign(sk_bytes, msg_bytes)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=f"Signing failed: {str(ex)}")

    return SignResponse(
        algorithm=res.algorithm.value,
        signature_hex=res.signature_hex,
        signature_b64=res.signature_b64,
        signature_size_bytes=res.signature_size,
        duration_ms=res.duration_ms,
        message_digest_preview=msg_bytes[:32].hex(),
    )


@router.post("/verify", response_model=VerifyResponse)
def verify_signature(payload: VerifyRequest):
    """
    Verify signature against public key and message.
    """
    signer = get_signer_instance(payload.algorithm)

    try:
        pk_bytes = bytes.fromhex(payload.public_key_hex.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex string for public_key_hex")

    try:
        sig_bytes = bytes.fromhex(payload.signature_hex.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex string for signature_hex")

    if payload.is_message_hex:
        try:
            msg_bytes = bytes.fromhex(payload.message.strip())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid hex string for message")
    else:
        msg_bytes = payload.message.encode("utf-8")

    outcome = signer.verify(pk_bytes, msg_bytes, sig_bytes)

    return VerifyResponse(
        algorithm=outcome.algorithm.value,
        valid=outcome.valid,
        duration_ms=outcome.duration_ms,
        error_message=outcome.error_message,
    )


@router.post("/tamper-test")
def run_tamper_test(payload: TamperTestRequest):
    """
    Execute full cryptographic tamper test suite (authentic, modified message,
    corrupted signature, wrong public key).
    """
    signer = get_signer_instance(payload.algorithm)
    tester = TamperTester(signer)

    sample_msg = (
        payload.custom_message.encode("utf-8")
        if payload.custom_message
        else b"Q-CHAIN: VERIFY_MIGRATION_TRANSACTION_PAYLOAD_V1"
    )

    result = tester.run_suite(sample_message=sample_msg)
    return result.to_dict()


@router.post("/benchmark")
def run_benchmark(payload: BenchmarkRequest):
    """
    Execute live performance benchmarks and measure real keygen, sign, and verify latency,
    sizes, and on-chain gas overhead.
    """
    benchmarker = PQCBenchmarker()

    if payload.algorithm and payload.algorithm.lower() not in ["all", "compare"]:
        signer = get_signer_instance(payload.algorithm)
        rep = benchmarker.benchmark_scheme(signer, trials=payload.trials)
        return {"benchmark": rep.to_dict()}
    else:
        comparison = benchmarker.run_comparative_benchmark(
            trials=payload.trials,
            include_all_mldsa_levels=True,
        )
        return comparison

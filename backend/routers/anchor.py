"""
Blockchain Anchoring & Verification Router
==========================================
Anchors canonical report hashes to smart contract and validates report integrity.

Owner: Member 3 & Member 4
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from shared.models import (
    AnchorRequest,
    AnchorRecord,
    VerifyHashRequest,
    VerifyHashResponse,
)
from shared.crypto_utils import compute_report_hash
from backend.services.anchoring_service import anchoring_service
from backend.services.pipeline_coordinator import pipeline_coordinator

router = APIRouter(prefix="/api/anchor", tags=["Anchoring"])
root_anchor_router = APIRouter(tags=["Anchoring Aliases"])


def validate_report_hash_format(h: str):
    """Ensures input hash is a valid 32-byte 0x-prefixed hexadecimal string."""
    if not h.startswith("0x") or len(h) != 66:
        raise ValueError(f"Invalid report hash '{h}'. Expected 0x-prefixed 32-byte hex string (66 characters).")
    try:
        int(h[2:], 16)
    except ValueError:
        raise ValueError(f"Invalid hexadecimal characters in hash '{h}'.")


class FlexibleAnchorRequest(BaseModel):
    hash: Optional[str] = None
    report_hash: Optional[str] = None
    scan_id: Optional[str] = "SCAN-LIVE-001"
    network: Optional[str] = "anvil"
    submitter: Optional[str] = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


class UniversalAnchorResponse(BaseModel):
    success: bool = True
    report_hash: str
    tx_hash: str
    transactionHash: str
    submitter: str
    timestamp: int
    block_number: int
    blockNumber: int
    network: str
    status: str
    contractAddress: str = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    canonicalHash: str
    anchoredAt: str
    gasUsed: int = 44210


class UniversalVerifyResponse(VerifyHashResponse):
    match: bool = True
    status: str = "MATCH"
    anchored: bool = True
    submitter: Optional[str] = None
    timestamp: Optional[int] = None
    block_number: Optional[int] = None
    onChainRecord: Optional[Any] = None
    queriedHash: Optional[str] = None


class SimulateTamperRequest(BaseModel):
    canonical_json: str


class SimulateTamperResponse(BaseModel):
    original_hash: str
    tampered_json: str
    tampered_hash: str
    character_altered_at: int
    original_char: str
    altered_char: str


def _perform_anchor(request: FlexibleAnchorRequest) -> UniversalAnchorResponse:
    target_hash = request.report_hash or request.hash
    if not target_hash:
        raise ValueError("Missing 'report_hash' or 'hash' field in request.")
    validate_report_hash_format(target_hash)

    record = anchoring_service.anchor_hash(
        report_hash=target_hash,
        submitter=request.submitter or "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        network=request.network or "anvil",
    )

    if request.scan_id:
        report = pipeline_coordinator.get_report(request.scan_id)
        if report:
            report.anchor_record = record

    now_iso = datetime.now(timezone.utc).isoformat()
    return UniversalAnchorResponse(
        success=True,
        report_hash=record.report_hash,
        tx_hash=record.tx_hash,
        transactionHash=record.tx_hash,
        submitter=record.submitter,
        timestamp=record.timestamp,
        block_number=record.block_number,
        blockNumber=record.block_number,
        network=record.network,
        status=record.status,
        contractAddress="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        canonicalHash=record.report_hash,
        anchoredAt=now_iso,
        gasUsed=44210,
    )


def _perform_verify(report_hash: str) -> UniversalVerifyResponse:
    validate_report_hash_format(report_hash)
    base_verif = anchoring_service.verify_report(report_hash=report_hash)
    record = base_verif.record
    is_match = base_verif.match_status == "MATCH"
    now_ts = int(datetime.now(timezone.utc).timestamp())

    return UniversalVerifyResponse(
        report_hash=base_verif.report_hash,
        computed_hash=base_verif.computed_hash,
        match_status=base_verif.match_status,
        is_anchored=base_verif.is_anchored,
        record=record,
        verification_message=base_verif.verification_message,
        match=is_match,
        status=base_verif.match_status,
        anchored=base_verif.is_anchored,
        submitter=record.submitter if record else None,
        timestamp=record.timestamp if record else now_ts,
        block_number=record.block_number if record else None,
        onChainRecord={
            "reportCanonicalHash": report_hash,
            "contractAddress": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
            "chain": "Anvil Localhost",
            "transactionHash": record.tx_hash if record else "",
            "blockNumber": record.block_number if record else 42,
            "submitterAddress": record.submitter if record else "",
        } if record else None,
        queriedHash=report_hash,
    )


@router.post("", response_model=UniversalAnchorResponse)
def anchor_report(request: FlexibleAnchorRequest):
    """Anchors a canonical report SHA-256 hash on-chain."""
    return _perform_anchor(request)


@root_anchor_router.post("/anchor", response_model=UniversalAnchorResponse)
def anchor_report_root(request: FlexibleAnchorRequest):
    """Direct alias for POST /anchor (Member 5 frontend and Member 4 chain service)."""
    return _perform_anchor(request)


@router.get("/verify/{report_hash}", response_model=UniversalVerifyResponse)
def verify_hash(report_hash: str):
    """Checks if a canonical report hash exists on the blockchain registry."""
    return _perform_verify(report_hash)


@root_anchor_router.get("/verify/{report_hash}", response_model=UniversalVerifyResponse)
def verify_hash_root(report_hash: str):
    """Direct alias for GET /verify/{hash} (Member 5 frontend and Member 4 chain service)."""
    return _perform_verify(report_hash)


@router.post("/verify/tamper-check", response_model=VerifyHashResponse)
def verify_tamper(request: VerifyHashRequest):
    """
    Live Tamper-Resistance Demonstration:
    Re-computes the SHA-256 hash of the uploaded canonical JSON and checks
    if it matches the anchored hash. Detects 1-character modifications.
    """
    validate_report_hash_format(request.report_hash)
    return anchoring_service.verify_report(
        report_hash=request.report_hash,
        canonical_json=request.canonical_json,
    )


@router.post("/simulate-tamper", response_model=SimulateTamperResponse)
def simulate_tamper(request: SimulateTamperRequest):
    """
    Demonstration helper for Member 5's live pitch demo:
    Flips a single character in the provided canonical JSON to prove that even a 1-byte
    modification generates a completely divergent SHA-256 hash that fails verification.
    """
    text = request.canonical_json
    if len(text) < 10:
        raise HTTPException(status_code=400, detail="JSON string too short to simulate tamper")

    target_idx = text.find("1")
    if target_idx == -1:
        target_idx = len(text) // 2

    orig_char = text[target_idx]
    altered_char = "9" if orig_char != "9" else "8"
    tampered_text = text[:target_idx] + altered_char + text[target_idx + 1:]

    orig_hash = compute_report_hash(text)
    tampered_hash = compute_report_hash(tampered_text)

    return SimulateTamperResponse(
        original_hash=orig_hash,
        tampered_json=tampered_text,
        tampered_hash=tampered_hash,
        character_altered_at=target_idx,
        original_char=orig_char,
        altered_char=altered_char,
    )

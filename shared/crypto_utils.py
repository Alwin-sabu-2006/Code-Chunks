"""
Q-Chain Canonical Serialization & Hashing Utility
=================================================
Provides deterministic canonical JSON serialization and SHA-256 / Keccak-256 hashing.
Ensures that Report integrity verification is 100% deterministic across all platforms.

Owner: Member 3 (Backend and MCP Engineer)
"""

import hashlib
import json
from typing import Any, Dict, Tuple


def serialize_canonical_json(data: Dict[str, Any]) -> str:
    """
    Serializes a dictionary to canonical JSON:
    - Keys sorted recursively at all depths
    - Strict separators (',', ':') with zero extraneous whitespace
    - UTF-8 clean encoding
    """
    def _sort_recursive(item: Any) -> Any:
        if isinstance(item, dict):
            return {k: _sort_recursive(v) for k, v in sorted(item.items())}
        elif isinstance(item, list):
            return [_sort_recursive(x) for x in item]
        return item

    sorted_data = _sort_recursive(data)
    return json.dumps(sorted_data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_report_hash(canonical_json: str) -> str:
    """
    Computes the SHA-256 hash of canonical JSON string with '0x' prefix.
    """
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return f"0x{digest}"


def compute_keccak256_hash(canonical_json: str) -> str:
    """
    Computes standard Keccak-256 (Ethereum compatibility) if pycryptodome/eth-hash is present,
    or falls back to sha256.
    """
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(canonical_json.encode("utf-8"))
        return f"0x{k.hexdigest()}"
    except ImportError:
        # Standard fallback if eth library not yet installed
        return compute_report_hash(canonical_json)


def verify_canonical_integrity(canonical_json: str, expected_hash: str) -> Tuple[bool, str]:
    """
    Checks if canonical_json matches expected_hash.
    Returns (is_match, computed_hash).
    """
    computed = compute_report_hash(canonical_json)
    # Check normalized lower-case
    is_match = computed.lower() == expected_hash.lower()
    return is_match, computed

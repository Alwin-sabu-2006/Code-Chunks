"""
Unit Tests for Cryptographic Signers (Classical, PQC, Hybrid).
"""

import pytest
from crypto.registry import CryptoRegistry
from crypto.base import CryptoSigner


@pytest.mark.parametrize("algo_id", CryptoRegistry.list_algorithms())
def test_algorithm_lifecycle(algo_id: str):
    """Test key generation, signing, and successful verification for each algorithm."""
    signer = CryptoRegistry.get_signer(algo_id)
    assert isinstance(signer, CryptoSigner)

    # 1. Keygen
    pk, sk = signer.keygen()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    assert len(pk) == signer.public_key_len, f"PK length mismatch for {algo_id}"
    assert len(sk) == signer.private_key_len, f"SK length mismatch for {algo_id}"

    # 2. Sign
    message = b"Testing Q-Chain PQC Signatures 2026"
    sig = signer.sign(message, sk)
    assert isinstance(sig, bytes)
    assert len(sig) == signer.signature_len, f"Sig length mismatch for {algo_id}"

    # 3. Verify
    is_valid = signer.verify(message, sig, pk)
    assert is_valid is True, f"Verification failed for authentic signature on {algo_id}"


@pytest.mark.parametrize("algo_id", CryptoRegistry.list_algorithms())
def test_export_keypair_and_result(algo_id: str):
    """Test typed Pydantic export helpers."""
    signer = CryptoRegistry.get_signer(algo_id)
    pk, sk = signer.keygen()
    kp = signer.export_keypair(pk, sk)
    assert kp.algorithm == signer.algorithm_id
    assert kp.public_key_hex == pk.hex()
    assert kp.public_key_bytes_len == len(pk)

    message = b"Typed Pydantic Schema Export Message"
    res = signer.sign_message_result(message, sk, pk)
    assert res.algorithm == signer.algorithm_id
    assert res.signature_bytes_len == signer.signature_len
    assert res.message_hex == message.hex()

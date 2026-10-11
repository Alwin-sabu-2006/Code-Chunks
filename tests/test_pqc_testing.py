"""
Automated Unit and Integration Tests for Q-Chain PQC Signature Testing Module.
Covers functional operations, all 4 tamper scenarios, performance benchmarking,
and FastAPI REST endpoints.
Part of Q-Chain Platform (Member 2 Deliverable).
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure root directory is on Python path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from backend.pqc_testing.base import ParameterSetId, ALGORITHM_CATALOG
from backend.pqc_testing.mldsa_signer import MLDSASigner
from backend.pqc_testing.ecdsa_signer import ECDSABaselineSigner
from backend.pqc_testing.tamper_tester import TamperTester
from backend.pqc_testing.benchmarker import PQCBenchmarker
from backend.pqc_testing.router import router


class TestMLDSASigner:
    """Tests for Module-Lattice-Based Digital Signature Algorithm (FIPS 204)."""

    def test_mldsa_44_keygen_sizes(self):
        signer = MLDSASigner(ParameterSetId.ML_DSA_44)
        kp = signer.generate_keypair()

        # FIPS 204 ML-DSA-44 standard specifications
        assert len(kp.public_key) == 1312
        assert len(kp.private_key) == 2528
        assert kp.public_key_size == 1312
        assert kp.private_key_size == 2528
        assert len(kp.public_key_hex) == 1312 * 2

    def test_mldsa_sign_and_verify_authentic(self):
        signer = MLDSASigner(ParameterSetId.ML_DSA_44)
        kp = signer.generate_keypair()
        message = b"Quantum-safe transaction #1001 authorization"

        sig_res = signer.sign(kp.private_key, message)
        assert len(sig_res.signature) == 2420  # FIPS 204 ML-DSA-44 signature size
        assert sig_res.duration_ms > 0

        verify_res = signer.verify(kp.public_key, message, sig_res.signature)
        assert verify_res.valid is True
        assert verify_res.error_message is None
        assert verify_res.duration_ms > 0

    def test_mldsa_tamper_modified_message_fails(self):
        signer = MLDSASigner(ParameterSetId.ML_DSA_44)
        kp = signer.generate_keypair()
        message = b"Send 10 ETH"
        sig_res = signer.sign(kp.private_key, message)

        # Altered message
        tampered_msg = b"Send 99 ETH"
        verify_res = signer.verify(kp.public_key, tampered_msg, sig_res.signature)
        assert verify_res.valid is False

    def test_mldsa_tamper_corrupted_signature_fails(self):
        signer = MLDSASigner(ParameterSetId.ML_DSA_44)
        kp = signer.generate_keypair()
        message = b"Report Hash: 0xabcdef123456"
        sig_res = signer.sign(kp.private_key, message)

        # Corrupt 1 byte in signature
        corrupted_sig = bytearray(sig_res.signature)
        corrupted_sig[100] ^= 0x01
        verify_res = signer.verify(kp.public_key, message, bytes(corrupted_sig))
        assert verify_res.valid is False

    def test_mldsa_tamper_wrong_public_key_fails(self):
        signer = MLDSASigner(ParameterSetId.ML_DSA_44)
        kp1 = signer.generate_keypair()
        kp2 = signer.generate_keypair()
        message = b"Anchor Transaction Block #512"
        sig_res = signer.sign(kp1.private_key, message)

        # Verify against alternative public key
        verify_res = signer.verify(kp2.public_key, message, sig_res.signature)
        assert verify_res.valid is False

    def test_mldsa_invalid_input_handling(self):
        signer = MLDSASigner(ParameterSetId.ML_DSA_44)
        kp = signer.generate_keypair()
        message = b"Payload"

        # Invalid private key size
        with pytest.raises(ValueError):
            signer.sign(b"too_short", message)

        # Verification with malformed public key length returns structured error instead of crashing
        v1 = signer.verify(b"bad_key", message, b"bad_sig")
        assert v1.valid is False
        assert "length mismatch" in v1.error_message


class TestECDSABaselineSigner:
    """Tests for Classical ECDSA (secp256k1) baseline."""

    def test_ecdsa_functional_and_tamper(self):
        signer = ECDSABaselineSigner()
        kp = signer.generate_keypair()
        assert len(kp.public_key) == 65  # SEC1 uncompressed
        assert len(kp.private_key) == 32

        msg = b"Classical Bitcoin/Ethereum Tx"
        sig_res = signer.sign(kp.private_key, msg)
        assert len(sig_res.signature) == 64  # Raw (r, s) compact

        v1 = signer.verify(kp.public_key, msg, sig_res.signature)
        assert v1.valid is True

        v2 = signer.verify(kp.public_key, b"Tampered Tx", sig_res.signature)
        assert v2.valid is False


class TestTamperTestSuite:
    """Tests the 4-scenario tamper test matrix runner."""

    def test_tamper_tester_full_matrix(self):
        signer = MLDSASigner(ParameterSetId.ML_DSA_44)
        tester = TamperTester(signer)
        result = tester.run_suite(b"Q-Chain Smart Contract Audit Payload")

        assert result.total_scenarios == 4
        assert result.passed_scenarios == 4
        assert result.tamper_detection_rate_pct == 100.0
        assert result.all_passed is True

        scenario_ids = [s.scenario_id for s in result.scenarios]
        assert "TAMPER_SCENARIO_1_AUTHENTIC" in scenario_ids
        assert "TAMPER_SCENARIO_2_MODIFIED_MESSAGE" in scenario_ids
        assert "TAMPER_SCENARIO_3_CORRUPTED_SIGNATURE" in scenario_ids
        assert "TAMPER_SCENARIO_4_WRONG_PUBLIC_KEY" in scenario_ids


class TestBenchmarker:
    """Tests performance benchmarking harness."""

    def test_benchmarker_live_runs(self):
        benchmarker = PQCBenchmarker()
        signer = MLDSASigner(ParameterSetId.ML_DSA_44)
        report = benchmarker.benchmark_scheme(signer, trials=2, warmup_runs=1)

        assert report.trials == 2
        assert report.keygen_stats.mean > 0
        assert report.sign_stats.mean > 0
        assert report.verify_stats.mean > 0
        assert report.public_key_size_bytes == 1312
        assert report.signature_size_bytes == 2420
        assert report.on_chain_costs.relative_overhead_vs_ecdsa > 1.0


class TestFastAPIRouter:
    """Tests the REST API endpoints."""

    @pytest.fixture
    def client(self):
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_api_algorithms(self, client):
        resp = client.get("/api/pqc/algorithms")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 4
        ids = [item["id"] for item in data]
        assert "ML-DSA-44" in ids
        assert "ECDSA-secp256k1" in ids

    def test_api_keygen_sign_verify_flow(self, client):
        # 1. KeyGen
        kg_resp = client.post("/api/pqc/keygen", json={"algorithm": "ML-DSA-44", "include_private_key": True})
        assert kg_resp.status_code == 200
        kg_data = kg_resp.json()
        pk_hex = kg_data["public_key_hex"]
        sk_hex = kg_data["private_key_hex"]
        assert pk_hex is not None and sk_hex is not None

        # 2. Sign
        msg = "Q-Chain Report Anchored Hash 0x12345"
        sign_resp = client.post("/api/pqc/sign", json={
            "algorithm": "ML-DSA-44",
            "private_key_hex": sk_hex,
            "message": msg,
        })
        assert sign_resp.status_code == 200
        sig_data = sign_resp.json()
        sig_hex = sig_data["signature_hex"]

        # 3. Verify Authentic
        verify_resp = client.post("/api/pqc/verify", json={
            "algorithm": "ML-DSA-44",
            "public_key_hex": pk_hex,
            "signature_hex": sig_hex,
            "message": msg,
        })
        assert verify_resp.status_code == 200
        assert verify_resp.json()["valid"] is True

        # 4. Verify Tampered
        verify_tampered = client.post("/api/pqc/verify", json={
            "algorithm": "ML-DSA-44",
            "public_key_hex": pk_hex,
            "signature_hex": sig_hex,
            "message": "Tampered Message",
        })
        assert verify_tampered.status_code == 200
        assert verify_tampered.json()["valid"] is False

    def test_api_tamper_test(self, client):
        resp = client.post("/api/pqc/tamper-test", json={"algorithm": "ML-DSA-44"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["all_passed"] is True
        assert data["tamper_detection_rate_pct"] == 100.0

    def test_api_benchmark(self, client):
        resp = client.post("/api/pqc/benchmark", json={"algorithm": "ML-DSA-44", "trials": 2})
        assert resp.status_code == 200
        data = resp.json()
        assert "benchmark" in data
        assert data["benchmark"]["algorithm_id"] == "ML-DSA-44"

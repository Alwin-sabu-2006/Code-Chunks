"""
Code Analysis Rules
"""
from shared.models import CryptoContext, QuantumRiskLevel
import re
from typing import Dict, List, Any

RULES: List[Dict[str, Any]] = [
    # Solidity Rules
    {
        "id": "RULE-SOL-001",
        "name": "Solidity ecrecover Call",
        "pattern": r"\becrecover\s*\(",
        "algorithm": "ecrecover_secp256k1",
        "context": CryptoContext.VERIFICATION,
        "quantum_risk": QuantumRiskLevel.CRITICAL,
        "confidence": 0.99,
        "explanation": "Solidity's native `ecrecover` validates secp256k1 signatures, which can be forged by Shor's algorithm.",
        "suggested_replacement": "ML-DSA-65 (via precompile or off-chain state verification)",
        "file_extensions": [".sol"]
    },
    {
        "id": "RULE-SOL-002",
        "name": "ECDSA Library Usage",
        "pattern": r"\bECDSA\.recover\s*\(|\busing\s+ECDSA\s+for\b",
        "algorithm": "OpenZeppelin_ECDSA",
        "context": CryptoContext.VERIFICATION,
        "quantum_risk": QuantumRiskLevel.CRITICAL,
        "confidence": 0.95,
        "explanation": "OpenZeppelin ECDSA library operates on elliptic curves vulnerable to quantum polynomial-time discrete log solving.",
        "suggested_replacement": "Falcon-512 or ML-DSA-65",
        "file_extensions": [".sol"]
    },
    {
        "id": "RULE-SOL-003",
        "name": "EIP-712 Typed Data Verification",
        "pattern": r"\b_hashTypedDataV4\s*\(|\bEIP712\b",
        "algorithm": "EIP-712_ECDSA",
        "context": CryptoContext.VERIFICATION,
        "quantum_risk": QuantumRiskLevel.HIGH,
        "confidence": 0.90,
        "explanation": "EIP-712 structured data hashing is classically paired with secp256k1 signature verification.",
        "suggested_replacement": "Post-Quantum EIP-712 container with ML-DSA-65 signature",
        "file_extensions": [".sol"]
    },

    # JavaScript / TypeScript (Ethers, Web3, BitcoinJS)
    {
        "id": "RULE-JS-001",
        "name": "ethers.Wallet Signing",
        "pattern": r"\bethers\.Wallet\b|\bnew\s+Wallet\s*\(",
        "algorithm": "ethers_Wallet_secp256k1",
        "context": CryptoContext.KEY_GENERATION,
        "quantum_risk": QuantumRiskLevel.CRITICAL,
        "confidence": 0.95,
        "explanation": "ethers.Wallet instantiates private keys over the classical secp256k1 elliptic curve.",
        "suggested_replacement": "PQC Keypair Manager (ML-DSA-65)",
        "file_extensions": [".js", ".ts", ".jsx", ".tsx"]
    },
    {
        "id": "RULE-JS-002",
        "name": "signMessage Call",
        "pattern": r"\.signMessage\s*\(|\.signTransaction\s*\(",
        "algorithm": "secp256k1_signMessage",
        "context": CryptoContext.SIGNING,
        "quantum_risk": QuantumRiskLevel.CRITICAL,
        "confidence": 0.92,
        "explanation": "Off-chain message signing using secp256k1 ECDSA private keys.",
        "suggested_replacement": "ML-DSA-65 / FIPS 204 sign",
        "file_extensions": [".js", ".ts", ".jsx", ".tsx"]
    },
    {
        "id": "RULE-JS-003",
        "name": "web3.eth.account Creation",
        "pattern": r"\bweb3\.eth\.accounts\.create\s*\(|\bweb3\.eth\.accounts\.sign\s*\(",
        "algorithm": "web3_account_ECDSA",
        "context": CryptoContext.KEY_GENERATION,
        "quantum_risk": QuantumRiskLevel.CRITICAL,
        "confidence": 0.95,
        "explanation": "Web3.js account generator creates 256-bit ECDSA keys.",
        "suggested_replacement": "ML-DSA-65 keygen",
        "file_extensions": [".js", ".ts", ".jsx", ".tsx"]
    },
    {
        "id": "RULE-JS-004",
        "name": "bitcoinjs-lib ECPair",
        "pattern": r"\bECPair\.fromWIF\s*\(|\bECPair\.makeRandom\s*\(|\becc\.sign\s*\(",
        "algorithm": "bitcoinjs_ECPair_secp256k1",
        "context": CryptoContext.KEY_GENERATION,
        "quantum_risk": QuantumRiskLevel.CRITICAL,
        "confidence": 0.95,
        "explanation": "Bitcoin elliptic curve key management vulnerable to quantum state recovery.",
        "suggested_replacement": "SLH-DSA or ML-DSA-87",
        "file_extensions": [".js", ".ts"]
    },
    {
        "id": "RULE-JS-005",
        "name": "Noble / Elliptic Secp256k1 library",
        "pattern": r"@noble/curves/secp256k1|\belliptic\.ec\s*\(\s*['\"]secp256k1['\"]\s*\)",
        "algorithm": "secp256k1_curve",
        "context": CryptoContext.GENERAL,
        "quantum_risk": QuantumRiskLevel.HIGH,
        "confidence": 0.94,
        "explanation": "Direct secp256k1 mathematical primitive usage.",
        "suggested_replacement": "FIPS 204 ML-DSA",
        "file_extensions": [".js", ".ts", ".json"]
    },
    {
        "id": "RULE-JS-006",
        "name": "Ed25519 Signing",
        "pattern": r"\bed25519\.sign\s*\(|\b@noble/ed25519\b",
        "algorithm": "ed25519_Edwards_Curve",
        "context": CryptoContext.SIGNING,
        "quantum_risk": QuantumRiskLevel.HIGH,
        "confidence": 0.91,
        "explanation": "Ed25519 elliptic-curve signature vulnerable to Shor's algorithm.",
        "suggested_replacement": "SLH-DSA-SHAKE-128s or ML-DSA-44",
        "file_extensions": [".js", ".ts"]
    },

    # Python Rules
    {
        "id": "RULE-PY-001",
        "name": "Python EC Key Generation (SECP256K1 / Hazmat / eth-account)",
        "pattern": r"\bec\.generate_private_key\s*\(|\bec\.SECP256K1\s*\(|\bSECP256k1\b|\becdsa\.SigningKey\.generate\s*\(|\bAccount\.create\s*\(|\bAccount\.from_key\s*\(|\bcoincurve\.PrivateKey\b",
        "algorithm": "ec.SECP256K1",
        "context": CryptoContext.KEY_GENERATION,
        "quantum_risk": QuantumRiskLevel.CRITICAL,
        "confidence": 0.98,
        "explanation": "Classical elliptic-curve key generation over secp256k1; Shor's algorithm polynomial-time discrete logarithm solving can recover the private key from public keys.",
        "suggested_replacement": "ML-DSA (FIPS 204), SLH-DSA (FIPS 205), or Falcon-512",
        "file_extensions": [".py"]
    },
    {
        "id": "RULE-PY-002",
        "name": "Python ECDSA Sign and Verify (Hazmat / eth-account)",
        "pattern": r"\bec\.ECDSA\s*\(|\bAccount\.sign_message\s*\(|\bAccount\.sign_transaction\s*\(|\bencode_defunct\s*\(",
        "algorithm": "ec.ECDSA",
        "context": CryptoContext.SIGNING,
        "quantum_risk": QuantumRiskLevel.CRITICAL,
        "confidence": 0.96,
        "explanation": "ECDSA signatures are forgeable once the classical private key is recovered via Shor's algorithm.",
        "suggested_replacement": "ML-DSA-65 (FIPS 204) or Falcon-512",
        "file_extensions": [".py"]
    },
    {
        "id": "RULE-PY-003",
        "name": "On-Chain Raw Public Key Exposure in Transaction",
        "pattern": r"\bsender_pub\s*:\s*(?:str|bytes)\b|\braw_public_key\b",
        "algorithm": "raw_public_key_exposure",
        "context": CryptoContext.VERIFICATION,
        "quantum_risk": QuantumRiskLevel.HIGH,
        "confidence": 0.92,
        "explanation": "The raw public key is stored and exposed with transactions on-chain at spend time, exposing it to quantum adversaries for private key extraction.",
        "suggested_replacement": "Quantum-resistant signature migration and hash-based identity commitments",
        "file_extensions": [".py"]
    },
    {
        "id": "RULE-PY-004",
        "name": "Python RSA Key Generation and PKCS#1 v1.5 / OAEP Padding",
        "pattern": r"\brsa\.generate_private_key\s*\(|\bpadding\.PKCS1v15\s*\(|\bpadding\.OAEP\s*\(",
        "algorithm": "RSA_2048_PKCS1v15",
        "context": CryptoContext.KEY_GENERATION,
        "quantum_risk": QuantumRiskLevel.CRITICAL,
        "confidence": 0.97,
        "explanation": "RSA integer factorization falls to Shor's algorithm in polynomial time, compromising identity keys and signatures.",
        "suggested_replacement": "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
        "file_extensions": [".py"]
    },
    {
        "id": "RULE-PY-005",
        "name": "Python Elliptic-Curve Diffie-Hellman Key Agreement (ECDH P-256)",
        "pattern": r"\bec\.ECDH\s*\(|\bec\.SECP256R1\s*\(",
        "algorithm": "ec.ECDH_P256",
        "context": CryptoContext.GENERAL,
        "quantum_risk": QuantumRiskLevel.CRITICAL,
        "confidence": 0.95,
        "explanation": "Classical ECDH key exchange is vulnerable to Shor's algorithm; recorded handshakes can be decrypted later by quantum adversaries (Harvest Now, Decrypt Later).",
        "suggested_replacement": "ML-KEM-768 (FIPS 203) or Hybrid P-256 + ML-KEM",
        "file_extensions": [".py"]
    }
]


def compile_rules():
    compiled = []
    for r in RULES:
        rule_copy = dict(r)
        rule_copy["compiled_regex"] = re.compile(r["pattern"], re.MULTILINE | re.IGNORECASE)
        compiled.append(rule_copy)
    return compiled


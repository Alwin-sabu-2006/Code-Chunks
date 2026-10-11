"""
Q-Chain Cryptographic Analysis Rule Definitions
Covers 25 detection rules for JavaScript, TypeScript, Python, and Solidity.
Identifies classical quantum-vulnerable cryptography (secp256k1, ECDSA, RSA, Ed25519, ecrecover).
"""

from dataclasses import dataclass
from typing import List, Pattern
import re

@dataclass
class DetectionRule:
    rule_id: str
    name: str
    languages: List[str]
    algorithm: str
    context: str  # key_generation, signing, verification, hash_and_sign, storage
    quantum_risk: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float
    regex_patterns: List[Pattern]
    description: str
    recommendation: str

RULES: List[DetectionRule] = [
    # ---------------------------------------------------------
    # SOLIDITY RULES
    # ---------------------------------------------------------
    DetectionRule(
        rule_id="QC-SOL-001",
        name="Solidity ecrecover Precompile Usage",
        languages=["solidity"],
        algorithm="secp256k1",
        context="verification",
        quantum_risk="CRITICAL",
        confidence=0.98,
        regex_patterns=[
            re.compile(r"\becrecover\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*[^)]+\)", re.IGNORECASE),
        ],
        description="Native EVM ecrecover precompile (address 0x01) used for recovering secp256k1 signer address. Vulnerable to Shor's algorithm polynomial-time discrete logarithm solving.",
        recommendation="Plan migration to account abstraction (ERC-4337) or hybrid off-chain PQC verification with ML-DSA (FIPS 204) state anchors."
    ),
    DetectionRule(
        rule_id="QC-SOL-002",
        name="OpenZeppelin ECDSA Recover Library",
        languages=["solidity"],
        algorithm="ECDSA",
        context="verification",
        quantum_risk="CRITICAL",
        confidence=0.95,
        regex_patterns=[
            re.compile(r"\bECDSA\.recover\s*\(", re.IGNORECASE),
            re.compile(r"\busing\s+ECDSA\s+for\s+bytes32\b", re.IGNORECASE),
        ],
        description="OpenZeppelin ECDSA helper library for secp256k1 signature recovery. Susceptible to quantum public key forgery once cryptographically relevant quantum computers emerge.",
        recommendation="Replace direct ECDSA verification with quantum-resistant signature verifiers or dual-signature multi-sig schemes."
    ),
    DetectionRule(
        rule_id="QC-SOL-003",
        name="EthSignedMessageHash Hash-and-Sign Pattern",
        languages=["solidity"],
        algorithm="secp256k1",
        context="hash_and_sign",
        quantum_risk="HIGH",
        confidence=0.92,
        regex_patterns=[
            re.compile(r"\bMessageHashUtils\.toEthSignedMessageHash\s*\(", re.IGNORECASE),
            re.compile(r"\btoEthSignedMessageHash\s*\(", re.IGNORECASE),
            re.compile(r'"\\x19Ethereum\s+Signed\s+Message:\s*\\n32"', re.IGNORECASE),
        ],
        description="EIP-191 personal_sign hash-and-sign framing pattern bound to classical secp256k1 signing flow.",
        recommendation="Decouple signature envelopes to accommodate PQC signatures with larger digest headers and stateful hash structures."
    ),
    DetectionRule(
        rule_id="QC-SOL-004",
        name="ERC-1271 SignatureChecker Verification",
        languages=["solidity"],
        algorithm="ECDSA",
        context="verification",
        quantum_risk="HIGH",
        confidence=0.90,
        regex_patterns=[
            re.compile(r"\bSignatureChecker\.isValidSignatureNow\s*\(", re.IGNORECASE),
            re.compile(r"\bisValidSignature\s*\(\s*bytes32\s*,\s*bytes\s*\)", re.IGNORECASE),
        ],
        description="ERC-1271 smart contract signature validator typically resolving to classical ECDSA externally-owned account validations.",
        recommendation="Ensure the target contract's isValidSignature implementation verifies NIST PQC standards (e.g. ML-DSA-44 or Falcon-512)."
    ),

    # ---------------------------------------------------------
    # JAVASCRIPT / TYPESCRIPT - ETHERS & WEB3 RULES
    # ---------------------------------------------------------
    DetectionRule(
        rule_id="QC-ETH-001",
        name="Ethers Wallet Key Generation / Instantiation",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="key_generation",
        quantum_risk="CRITICAL",
        confidence=0.95,
        regex_patterns=[
            re.compile(r"\bethers\.Wallet\.createRandom\s*\(", re.IGNORECASE),
            re.compile(r"\bnew\s+(?:ethers\.)?Wallet\s*\(", re.IGNORECASE),
            re.compile(r"\bWallet\.fromMnemonic\s*\(", re.IGNORECASE),
            re.compile(r"\bHDNodeWallet\.createRandom\s*\(", re.IGNORECASE),
        ],
        description="Generates or initializes classical secp256k1 private/public keypair. A quantum adversary running Shor's algorithm can derive the private key from the public key.",
        recommendation="Introduce post-quantum key encapsulation or dual-key generation pairing ML-DSA-65 with secp256k1."
    ),
    DetectionRule(
        rule_id="QC-ETH-002",
        name="Ethers Message Signing",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="signing",
        quantum_risk="CRITICAL",
        confidence=0.95,
        regex_patterns=[
            re.compile(r"\b(?:wallet|signer)\.signMessage\s*\(", re.IGNORECASE),
            re.compile(r"\bpersonal_sign\b", re.IGNORECASE),
        ],
        description="Signs message digest using classical secp256k1 curve parameters yielding a 65-byte ECDSA signature (r, s, v).",
        recommendation="Upgrade to NIST PQC signature algorithms (ML-DSA-44/65 or Falcon-512) for off-chain message attestation."
    ),
    DetectionRule(
        rule_id="QC-ETH-003",
        name="Ethers Transaction Signing",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="signing",
        quantum_risk="CRITICAL",
        confidence=0.96,
        regex_patterns=[
            re.compile(r"\b(?:wallet|signer)\.signTransaction\s*\(", re.IGNORECASE),
            re.compile(r"\bsendTransaction\s*\(", re.IGNORECASE),
        ],
        description="Generates raw signed Ethereum transaction payload with ECDSA secp256k1 authorization.",
        recommendation="Note: Layer 1 transaction authorization currently requires ECDSA; isolate transaction signing from application-level data attestation."
    ),
    DetectionRule(
        rule_id="QC-ETH-004",
        name="Ethers Message Verification",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="verification",
        quantum_risk="CRITICAL",
        confidence=0.94,
        regex_patterns=[
            re.compile(r"\bethers\.verifyMessage\s*\(", re.IGNORECASE),
            re.compile(r"\bethers\.utils\.verifyMessage\s*\(", re.IGNORECASE),
        ],
        description="Verifies ECDSA signature over string/bytes message by recovering secp256k1 public key.",
        recommendation="Replace with lattice-based verification harness (liboqs / ML-DSA verify)."
    ),
    DetectionRule(
        rule_id="QC-ETH-005",
        name="Ethers SigningKey / Raw Elliptic Curve Utility",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="key_generation",
        quantum_risk="HIGH",
        confidence=0.93,
        regex_patterns=[
            re.compile(r"\bethers\.SigningKey\s*\(", re.IGNORECASE),
            re.compile(r"\bcomputePublicKey\s*\(", re.IGNORECASE),
            re.compile(r"\bSigningKey\.computePublicKey\s*\(", re.IGNORECASE),
        ],
        description="Direct invocation of secp256k1 point multiplication to derive uncompressed/compressed public keys.",
        recommendation="Transition key management to lattice polynomial structures (FIPS 204 module-lattice vectors)."
    ),
    DetectionRule(
        rule_id="QC-ETH-006",
        name="EIP-712 Typed Data Signing",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="signing",
        quantum_risk="CRITICAL",
        confidence=0.95,
        regex_patterns=[
            re.compile(r"\b(?:wallet|signer)\.signTypedData\s*\(", re.IGNORECASE),
            re.compile(r"\b_signTypedData\s*\(", re.IGNORECASE),
            re.compile(r"\beth_signTypedData_v4\b", re.IGNORECASE),
        ],
        description="Structured data signing using EIP-712 protocol backed by secp256k1 ECDSA signatures.",
        recommendation="Wrap typed schema payloads with post-quantum envelopes (e.g. SLH-DSA / ML-DSA dual payload)."
    ),

    # ---------------------------------------------------------
    # WEB3.JS RULES
    # ---------------------------------------------------------
    DetectionRule(
        rule_id="QC-WEB3-001",
        name="Web3.js Account Creation",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="key_generation",
        quantum_risk="CRITICAL",
        confidence=0.95,
        regex_patterns=[
            re.compile(r"\bweb3\.eth\.accounts\.create\s*\(", re.IGNORECASE),
            re.compile(r"\bweb3\.eth\.accounts\.privateKeyToAccount\s*\(", re.IGNORECASE),
        ],
        description="Generates secp256k1 private key and derived Ethereum account using Web3.js.",
        recommendation="Migrate to post-quantum key custody solutions supporting quantum-safe seed derivation."
    ),
    DetectionRule(
        rule_id="QC-WEB3-002",
        name="Web3.js Account Signature Generation",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="signing",
        quantum_risk="CRITICAL",
        confidence=0.95,
        regex_patterns=[
            re.compile(r"\bweb3\.eth\.accounts\.sign\s*\(", re.IGNORECASE),
            re.compile(r"\bweb3\.eth\.personal\.sign\s*\(", re.IGNORECASE),
        ],
        description="Signs arbitrary data using secp256k1 ECDSA via Web3.js account interface.",
        recommendation="Implement ML-DSA-44 or Falcon-512 signing alongside ECDSA in a hybrid migration model."
    ),
    DetectionRule(
        rule_id="QC-WEB3-003",
        name="Web3.js Account Signature Recovery",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="verification",
        quantum_risk="CRITICAL",
        confidence=0.94,
        regex_patterns=[
            re.compile(r"\bweb3\.eth\.accounts\.recover\s*\(", re.IGNORECASE),
            re.compile(r"\bweb3\.eth\.personal\.ecVerify\s*\(", re.IGNORECASE),
        ],
        description="Recovers Ethereum address from secp256k1 ECDSA signature.",
        recommendation="Replace with explicit public-key post-quantum verification functions."
    ),

    # ---------------------------------------------------------
    # BITCOIN / SECP256K1 LIBRARIES (JS / TS)
    # ---------------------------------------------------------
    DetectionRule(
        rule_id="QC-BTC-001",
        name="BitcoinJS / ECPair Keypair Creation",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="key_generation",
        quantum_risk="CRITICAL",
        confidence=0.96,
        regex_patterns=[
            re.compile(r"\bECPair\.makeRandom\s*\(", re.IGNORECASE),
            re.compile(r"\bECPair\.fromPrivateKey\s*\(", re.IGNORECASE),
            re.compile(r"\btiny-secp256k1\b", re.IGNORECASE),
            re.compile(r"\bbip32\.fromSeed\s*\(", re.IGNORECASE),
        ],
        description="Instantiates secp256k1 ECDSA/Schnorr keypairs via BitcoinJS-lib / tiny-secp256k1.",
        recommendation="Prepare Bitcoin scripts/taproot outputs for future quantum-safe soft-forks (e.g. Lamport/Winternitz or Falcon)."
    ),
    DetectionRule(
        rule_id="QC-BTC-002",
        name="BitcoinJS Transaction / PSBT Signing",
        languages=["javascript", "typescript"],
        algorithm="secp256k1",
        context="signing",
        quantum_risk="CRITICAL",
        confidence=0.95,
        regex_patterns=[
            re.compile(r"\bpsbt\.signInput\s*\(", re.IGNORECASE),
            re.compile(r"\bpsbt\.signAllInputs\s*\(", re.IGNORECASE),
            re.compile(r"\bkeyPair\.sign\s*\(", re.IGNORECASE),
        ],
        description="Generates ECDSA or Schnorr signatures over Bitcoin transaction inputs using secp256k1.",
        recommendation="Migrate off-chain governance and voting logic to NIST PQC standards."
    ),

    # ---------------------------------------------------------
    # PYTHON CRYPTOGRAPHY & WEB3 RULES
    # ---------------------------------------------------------
    DetectionRule(
        rule_id="QC-PY-001",
        name="Python eth_account & EC Key Generation",
        languages=["python"],
        algorithm="secp256k1",
        context="key_generation",
        quantum_risk="CRITICAL",
        confidence=0.96,
        regex_patterns=[
            re.compile(r"\bAccount\.create\s*\(", re.IGNORECASE),
            re.compile(r"\bAccount\.from_key\s*\(", re.IGNORECASE),
            re.compile(r"\beth_account\.Account\b", re.IGNORECASE),
            re.compile(r"\bec\.SECP256K1\s*\(", re.IGNORECASE),
            re.compile(r"\bec\.generate_private_key\s*\(", re.IGNORECASE),
        ],
        description="Creates secp256k1 Ethereum account keypairs or classical elliptic-curve keys.",
        recommendation="Pair with quantum-resistant key generation using liboqs-python (ML-DSA / FIPS 204)."
    ),
    DetectionRule(
        rule_id="QC-PY-002",
        name="Python eth_account & ECDSA Message / Transaction Signing",
        languages=["python"],
        algorithm="secp256k1",
        context="signing",
        quantum_risk="CRITICAL",
        confidence=0.96,
        regex_patterns=[
            re.compile(r"\baccount\.sign_message\s*\(", re.IGNORECASE),
            re.compile(r"\bAccount\.sign_message\s*\(", re.IGNORECASE),
            re.compile(r"\bAccount\.sign_transaction\s*\(", re.IGNORECASE),
            re.compile(r"\bencode_defunct\s*\(", re.IGNORECASE),
            re.compile(r"\bec\.ECDSA\s*\(", re.IGNORECASE),
        ],
        description="Generates secp256k1 ECDSA signatures for Ethereum messages or transactions in Python.",
        recommendation="Benchmark signature size overhead against ML-DSA and Falcon using Q-Chain harness."
    ),
    DetectionRule(
        rule_id="QC-PY-003",
        name="Python eth_account Signature Recovery",
        languages=["python"],
        algorithm="secp256k1",
        context="verification",
        quantum_risk="CRITICAL",
        confidence=0.95,
        regex_patterns=[
            re.compile(r"\bAccount\.recover_message\s*\(", re.IGNORECASE),
            re.compile(r"\bw3\.eth\.account\.recover_message\s*\(", re.IGNORECASE),
        ],
        description="Recovers Ethereum address from secp256k1 signature in Python backend.",
        recommendation="Implement post-quantum signature verification matrix with tamper resistance checks."
    ),
    DetectionRule(
        rule_id="QC-PY-004",
        name="Python Elliptic Curve Asymmetric Signing (hazmat / ecdsa)",
        languages=["python"],
        algorithm="ECDSA",
        context="signing",
        quantum_risk="CRITICAL",
        confidence=0.94,
        regex_patterns=[
            re.compile(r"\bec\.ECDSA\s*\(", re.IGNORECASE),
            re.compile(r"\bcoincurve\.PrivateKey\b", re.IGNORECASE),
            re.compile(r"\becdsa\.SigningKey\b", re.IGNORECASE),
        ],
        description="Uses Python cryptography hazmat or ecdsa library to create elliptic curve keys and signatures.",
        recommendation="Replace elliptic curve algorithms (NIST P-256, secp256k1) with lattice-based ML-DSA."
    ),
    DetectionRule(
        rule_id="QC-PY-005",
        name="Python Elliptic-Curve Diffie-Hellman Key Agreement (ECDH P-256)",
        languages=["python"],
        algorithm="ec.ECDH_P256",
        context="key_exchange",
        quantum_risk="CRITICAL",
        confidence=0.95,
        regex_patterns=[
            re.compile(r"\bec\.ECDH\s*\(", re.IGNORECASE),
            re.compile(r"\bec\.SECP256R1\s*\(", re.IGNORECASE),
        ],
        description="Classical ECDH key exchange is vulnerable to Shor's algorithm; recorded handshakes can be decrypted later by quantum adversaries (Harvest Now, Decrypt Later).",
        recommendation="ML-KEM-768 (FIPS 203) or Hybrid P-256 + ML-KEM"
    ),
    DetectionRule(
        rule_id="QC-PY-006",
        name="On-Chain Raw Public Key Exposure in Transaction",
        languages=["python"],
        algorithm="raw_public_key_exposure",
        context="verification",
        quantum_risk="HIGH",
        confidence=0.92,
        regex_patterns=[
            re.compile(r"\bsender_pub\s*:\s*(?:str|bytes)\b", re.IGNORECASE),
            re.compile(r"\braw_public_key\b", re.IGNORECASE),
        ],
        description="The raw public key is stored and exposed with transactions on-chain at spend time, exposing it to quantum adversaries for private key extraction.",
        recommendation="Quantum-resistant signature migration and hash-based identity commitments"
    ),

    # ---------------------------------------------------------
    # ED25519 RULES (JS / TS / PYTHON)
    # ---------------------------------------------------------
    DetectionRule(
        rule_id="QC-ED25519-001",
        name="Ed25519 Keypair Generation",
        languages=["javascript", "typescript", "python"],
        algorithm="Ed25519",
        context="key_generation",
        quantum_risk="HIGH",
        confidence=0.93,
        regex_patterns=[
            re.compile(r"\bnacl\.sign\.keyPair\s*\(", re.IGNORECASE),
            re.compile(r"\btweetnacl\.sign\.keyPair\b", re.IGNORECASE),
            re.compile(r"\bSigningKey\.generate\s*\(", re.IGNORECASE),
            re.compile(r"\bed25519\.Ed25519PrivateKey\.generate\s*\(", re.IGNORECASE),
        ],
        description="Generates Edwards-curve Ed25519 keypairs (commonly used in Solana, NEAR, Polkadot). Completely vulnerable to Shor's algorithm.",
        recommendation="Migrate to SLH-DSA (FIPS 205, stateless hash-based) or ML-DSA-44."
    ),
    DetectionRule(
        rule_id="QC-ED25519-002",
        name="Ed25519 Signature Signing and Verification",
        languages=["javascript", "typescript", "python"],
        algorithm="Ed25519",
        context="signing",
        quantum_risk="HIGH",
        confidence=0.92,
        regex_patterns=[
            re.compile(r"\bnacl\.sign\.detached\s*\(", re.IGNORECASE),
            re.compile(r"\bnacl\.sign\.detached\.verify\s*\(", re.IGNORECASE),
            re.compile(r"\bed25519\.sign\s*\(", re.IGNORECASE),
            re.compile(r"\bed25519\.verify\s*\(", re.IGNORECASE),
        ],
        description="Creates or verifies 64-byte Ed25519 signatures over messages. Shor's algorithm can recover private keys from exposed public keys.",
        recommendation="Replace with NIST PQC signature algorithm with minimal size footprint such as Falcon-512."
    ),

    # ---------------------------------------------------------
    # RSA RULES (JS / TS / PYTHON)
    # ---------------------------------------------------------
    DetectionRule(
        rule_id="QC-RSA-001",
        name="RSA Key Generation",
        languages=["javascript", "typescript", "python"],
        algorithm="RSA",
        context="key_generation",
        quantum_risk="CRITICAL",
        confidence=0.97,
        regex_patterns=[
            re.compile(r"\bcrypto\.generateKeyPairSync\s*\(\s*['\"]rsa['\"]", re.IGNORECASE),
            re.compile(r"\brsa\.generate_private_key\s*\(", re.IGNORECASE),
            re.compile(r"\bRSA\.generate\s*\(\s*(?:1024|2048|3072|4096)", re.IGNORECASE),
        ],
        description="Generates RSA integer factorization keys. Shor's algorithm factors RSA moduli N = p*q in polynomial time O((log N)^3).",
        recommendation="Immediately replace RSA with post-quantum ML-DSA for digital signatures or ML-KEM for key encapsulation."
    ),
    DetectionRule(
        rule_id="QC-RSA-002",
        name="RSA Sign and Verify Operations",
        languages=["javascript", "typescript", "python"],
        algorithm="RSA",
        context="signing",
        quantum_risk="CRITICAL",
        confidence=0.96,
        regex_patterns=[
            re.compile(r"\bcrypto\.createSign\s*\(\s*['\"](?:RSA-)?SHA256['\"]", re.IGNORECASE),
            re.compile(r"\bcrypto\.createVerify\s*\(\s*['\"](?:RSA-)?SHA256['\"]", re.IGNORECASE),
            re.compile(r"\bpadding\.PKCS1v15\s*\(", re.IGNORECASE),
            re.compile(r"\bpadding\.OAEP\s*\(", re.IGNORECASE),
            re.compile(r"\bpkcs1_15\.new\s*\(", re.IGNORECASE),
            re.compile(r"\bpss\.new\s*\(", re.IGNORECASE),
        ],
        description="Signs or verifies payloads using RSA PKCS#1 v1.5 or PSS padding. Vulnerable to quantum key recovery.",
        recommendation="Transition legacy identity and authorization mechanisms to NIST FIPS 204 (ML-DSA)."
    ),

    # ---------------------------------------------------------
    # HASH-AND-SIGN & LOW-LEVEL CRYPTO PATTERNS
    # ---------------------------------------------------------
    DetectionRule(
        rule_id="QC-HASH-001",
        name="Classical Hash-and-Sign Composite Pattern",
        languages=["javascript", "typescript", "python", "solidity"],
        algorithm="ECDSA",
        context="hash_and_sign",
        quantum_risk="HIGH",
        confidence=0.88,
        regex_patterns=[
            re.compile(r"\bkeccak256\s*\([^)]*\)\s*.*(?:sign|ecrecover)", re.IGNORECASE),
            re.compile(r"\bcreateHash\s*\(['\"]sha256['\"]\)\.update\([^)]*\)\.sign\b", re.IGNORECASE),
        ],
        description="Composite pipeline taking SHA-256 / Keccak-256 digest and immediately delegating to classical elliptic curve signature generation.",
        recommendation="Replace the signature sink of the digest with ML-DSA-44 or Falcon-512."
    ),
    DetectionRule(
        rule_id="QC-SEC-001",
        name="Hardcoded / Raw Secp256k1 Curve Parameter Reference",
        languages=["javascript", "typescript", "python", "solidity"],
        algorithm="secp256k1",
        context="storage",
        quantum_risk="HIGH",
        confidence=0.92,
        regex_patterns=[
            re.compile(r"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", re.IGNORECASE),
            re.compile(r"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", re.IGNORECASE),
            re.compile(r"\btiny-secp256k1\b", re.IGNORECASE),
            re.compile(r"\b@noble/curves/secp256k1\b", re.IGNORECASE),
        ],
        description="Explicit reference to secp256k1 field characteristic p or order n in custom elliptic curve arithmetic.",
        recommendation="Deprecate custom elliptic curve arithmetic; adopt lattice-based arithmetic modules for post-quantum safety."
    ),
]

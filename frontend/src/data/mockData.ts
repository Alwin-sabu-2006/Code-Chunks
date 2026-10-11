import { Finding, AlgorithmMetrics, VerificationResult, Report, AgentEvent, MCPCallLog } from '../types/schema';

export interface SampleApp {
  id: string;
  name: string;
  type: 'Token Wallet' | 'Voting dApp' | 'Multisig';
  description: string;
  filesCount: number;
  linesOfCode: number;
  plantedVulnerabilities: number;
  detectedCount: number;
  tags: string[];
}

export const SAMPLE_APPS: SampleApp[] = [
  {
    id: 'token-wallet',
    name: 'ERC-20 Token Wallet & Relayer',
    type: 'Token Wallet',
    description: 'Non-custodial web3 wallet utilizing ECDSA secp256k1 meta-transactions and permit signatures.',
    filesCount: 14,
    linesOfCode: 1840,
    plantedVulnerabilities: 4,
    detectedCount: 4,
    tags: ['Solidity', 'TypeScript', 'EIP-712', 'secp256k1'],
  },
  {
    id: 'voting-dapp',
    name: 'Governor Alpha Voting dApp',
    type: 'Voting dApp',
    description: 'On-chain DAO voting system using ECDSA signatures for delegated vote casting.',
    filesCount: 18,
    linesOfCode: 2450,
    plantedVulnerabilities: 3,
    detectedCount: 3,
    tags: ['Solidity', 'ecrecover', 'Governance'],
  },
  {
    id: 'multisig-vault',
    name: '3-of-5 Multisig Treasury Vault',
    type: 'Multisig',
    description: 'Enterprise treasury contract requiring multi-party ECDSA and Ed25519 threshold approvals.',
    filesCount: 22,
    linesOfCode: 3120,
    plantedVulnerabilities: 5,
    detectedCount: 5,
    tags: ['Solidity', 'ECDSA', 'Ed25519', 'Threshold'],
  },
];

export const MOCK_FINDINGS: Finding[] = [
  {
    id: 'QC-F01',
    file: 'contracts/TokenWallet.sol',
    line: 87,
    codeSnippet: `function executeMetaTx(bytes memory sig, bytes32 hash) public {\n    address signer = ecrecover(hash, v, r, s);\n    require(signer == owner, "Invalid ECDSA signature");\n    _transfer(signer, msg.sender, amount);\n}`,
    algorithm: 'ecrecover',
    context: 'signature_verification',
    quantumRisk: 'Shor\'s discrete logarithm algorithm completely compromises secp256k1 curve parameters in ~2n polynomial time, allowing full private key extraction from public transactions.',
    shorsImpact: 'Catastrophic: Attacker with CRQC (Cryptographically Relevant Quantum Computer) derives private key directly from public keys on-chain.',
    confidenceScore: 0.99,
    severity: 'CRITICAL',
    recommendedPqc: 'ML-DSA',
    explanation: 'The contract uses classical Ethereum ecrecover to authenticate transactions. Post-quantum attackers can forge signatures without access to the hardware wallet.',
  },
  {
    id: 'QC-F02',
    file: 'src/services/signer.ts',
    line: 42,
    codeSnippet: `const wallet = new ethers.Wallet(privateKey);\nconst signature = await wallet.signMessage(messageHash);\nreturn { r: signature.slice(0, 66), s: '0x' + signature.slice(66, 130) };`,
    algorithm: 'ECDSA',
    context: 'transaction_signing',
    quantumRisk: 'ECDSA with 256-bit keys provides zero quantum resistance against Shor\'s algorithm (NIST Security Category 0 against quantum adversary).',
    shorsImpact: 'Severe: Allows off-chain signature forgery and impersonation of wallet addresses.',
    confidenceScore: 0.96,
    severity: 'HIGH',
    recommendedPqc: 'ML-DSA',
    explanation: 'Client-side signing routine uses ethers.Wallet standard ECDSA. Needs dual hybrid signing or migration to ML-DSA (FIPS 204) lattice-based signature scheme.',
  },
  {
    id: 'QC-F03',
    file: 'contracts/DelegationRegistry.sol',
    line: 114,
    codeSnippet: `bytes32 messageDigest = keccak256(abi.encodePacked(delegator, delegatee, nonce));\naddress recovered = ECDSA.recover(messageDigest, signature);\nrequire(recovered != address(0), "ECDSA: invalid signature");`,
    algorithm: 'ECDSA',
    context: 'signature_verification',
    quantumRisk: 'OpenZeppelin ECDSA.recover wrapper internally uses secp256k1 elliptic curve mathematics vulnerable to quantum period-finding.',
    shorsImpact: 'High: Unauthorized vote delegation manipulation without delegator consent.',
    confidenceScore: 0.94,
    severity: 'HIGH',
    recommendedPqc: 'Falcon',
    explanation: 'Delegation verification relies on OpenZeppelin ECDSA library. For voting contracts where storage size is critical, Falcon-512 yields minimal footprint overhead.',
  },
  {
    id: 'QC-F04',
    file: 'src/crypto/keys.ts',
    line: 28,
    codeSnippet: `import { ec as EC } from 'elliptic';\nconst ec = new EC('secp256k1');\nconst keyPair = ec.genKeyPair();`,
    algorithm: 'secp256k1',
    context: 'key_generation',
    quantumRisk: 'secp256k1 key generation relies on discrete log hardness over finite fields, solvable by Shor\'s algorithm.',
    shorsImpact: 'Moderate: Generated keys are immediately exposed to retrospective store-now-decrypt-later attacks.',
    confidenceScore: 0.98,
    severity: 'MEDIUM',
    recommendedPqc: 'ML-DSA',
    explanation: 'Key generation generates classical elliptic curve keypairs without post-quantum entropy or lattice parameters.',
  },
  {
    id: 'QC-F05',
    file: 'contracts/MultisigValidator.sol',
    line: 65,
    codeSnippet: `bool valid = Ed25519.verify(message, signature, publicKey);\nrequire(valid, "Invalid Ed25519 signature");`,
    algorithm: 'ed25519',
    context: 'signature_verification',
    quantumRisk: 'Edwards-curve digital signature (Curve25519) is completely broken by quantum Shor algorithm (equivalent security weakness to ECDSA).',
    shorsImpact: 'High: Multisig quorum bypass by forging additional co-signer signatures.',
    confidenceScore: 0.95,
    severity: 'HIGH',
    recommendedPqc: 'SLH-DSA',
    explanation: 'Secondary multisig layer uses Ed25519. For conservative long-term security where stateless hash-based trees are desired, SLH-DSA provides highest assurance.',
  },
];

export const MOCK_BENCHMARKS: AlgorithmMetrics[] = [
  {
    name: 'ECDSA (secp256k1)',
    securityLevel: '128-bit (Classical Only)',
    isQuantumSafe: false,
    publicKeySize: 64,
    signatureSize: 64,
    keygenTimeUs: 48,
    signTimeUs: 72,
    verifyTimeUs: 88,
    gasEstimateUnits: 3000,
    standardizationStatus: 'Legacy / Pre-Quantum',
    tradeoffSummary: 'Tiny signature and key size, minimal gas cost, but ZERO protection against quantum attack.',
  },
  {
    name: 'ML-DSA (FIPS 204)',
    securityLevel: 'NIST Level 2 / 3 (Quantum-Safe)',
    isQuantumSafe: true,
    publicKeySize: 1312,
    signatureSize: 2420,
    keygenTimeUs: 64,
    signTimeUs: 142,
    verifyTimeUs: 98,
    gasEstimateUnits: 46200,
    standardizationStatus: 'FIPS 204 Standardized (August 2024)',
    tradeoffSummary: 'Recommended general standard. Fast lattice signing and verification with moderate signature overhead.',
  },
  {
    name: 'SLH-DSA (FIPS 205)',
    securityLevel: 'NIST Level 3 / 5 (Quantum-Safe)',
    isQuantumSafe: true,
    publicKeySize: 32,
    signatureSize: 7856,
    keygenTimeUs: 1240,
    signTimeUs: 8420,
    verifyTimeUs: 610,
    gasEstimateUnits: 148000,
    standardizationStatus: 'FIPS 205 Standardized (August 2024)',
    tradeoffSummary: 'Stateless hash-based security relying solely on hash collision resistance. Extremely secure, but larger signatures.',
  },
  {
    name: 'Falcon (FN-DSA)',
    securityLevel: 'NIST Level 1 / 5 (Quantum-Safe)',
    isQuantumSafe: true,
    publicKeySize: 897,
    signatureSize: 666,
    keygenTimeUs: 4200,
    signTimeUs: 610,
    verifyTimeUs: 74,
    gasEstimateUnits: 18400,
    standardizationStatus: 'NIST Draft (FN-DSA standardization pending)',
    tradeoffSummary: 'Smallest signature size among lattice algorithms and fastest verification, ideal for gas-constrained blockchain rollups.',
  },
];

export const MOCK_VERIFICATION: VerificationResult = {
  timestamp: new Date().toISOString(),
  overallTamperDetectionRate: 100.0,
  testIterations: 100,
  matrices: [
    {
      algorithm: 'ECDSA secp256k1 (Baseline)',
      tamperDetectionRate: 100,
      scenarios: [
        { scenario: 'Valid Signature', expectedResult: 'PASS', actualResult: 'PASS', passed: true, tamperDetected: false, details: 'Signature verified cleanly against message.' },
        { scenario: 'Flipped Message Bit', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Tampered byte 0x1A detected. Verification rejected.' },
        { scenario: 'Flipped Signature Bit', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Invalid signature scalar values.' },
        { scenario: 'Wrong Public Key', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Point recovery mismatch.' },
      ]
    },
    {
      algorithm: 'ML-DSA-44 (FIPS 204)',
      tamperDetectionRate: 100,
      scenarios: [
        { scenario: 'Valid Signature', expectedResult: 'PASS', actualResult: 'PASS', passed: true, tamperDetected: false, details: 'Lattice polynomial check verified.' },
        { scenario: 'Flipped Message Bit', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Shake256 hash commitment failure.' },
        { scenario: 'Flipped Signature Bit', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Norm bound verification exceeded.' },
        { scenario: 'Wrong Public Key', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Matrix syndrome mismatch.' },
      ]
    },
    {
      algorithm: 'SLH-DSA-SHAKE-128f (FIPS 205)',
      tamperDetectionRate: 100,
      scenarios: [
        { scenario: 'Valid Signature', expectedResult: 'PASS', actualResult: 'PASS', passed: true, tamperDetected: false, details: 'Merkle tree root authentication path verified.' },
        { scenario: 'Flipped Message Bit', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'FORS tree root mismatch.' },
        { scenario: 'Flipped Signature Bit', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Invalid leaf node authentication.' },
        { scenario: 'Wrong Public Key', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Top-level root hash collision check failed.' },
      ]
    },
    {
      algorithm: 'Falcon-512',
      tamperDetectionRate: 100,
      scenarios: [
        { scenario: 'Valid Signature', expectedResult: 'PASS', actualResult: 'PASS', passed: true, tamperDetected: false, details: 'NTRU lattice Gaussian sampling verified.' },
        { scenario: 'Flipped Message Bit', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Header checksum failure.' },
        { scenario: 'Flipped Signature Bit', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Polynomial coefficients corrupted.' },
        { scenario: 'Wrong Public Key', expectedResult: 'FAIL', actualResult: 'FAIL', passed: true, tamperDetected: true, details: 'Public key lattice unreduced.' },
      ]
    }
  ]
};

export const MOCK_AGENT_EVENTS: AgentEvent[] = [
  {
    id: 'evt-01',
    timestamp: '17:21:02',
    agent: 'Cryptographic Analysis Agent',
    type: 'agent_started',
    message: 'Initiated AST syntax tree pass on target repository (14 files).',
  },
  {
    id: 'evt-02',
    timestamp: '17:21:03',
    agent: 'Cryptographic Analysis Agent',
    type: 'tool_called',
    message: 'Invoked mcp-code-analysis:scan_ast_patterns (secp256k1, ecrecover, ethers.Wallet)',
    payload: { patternsScanned: 18, matchesFound: 5 },
  },
  {
    id: 'evt-03',
    timestamp: '17:21:04',
    agent: 'PQC Test Agent',
    type: 'agent_started',
    message: 'Commenced NIST FIPS 204 / 205 benchmark harness across liboqs algorithms.',
  },
  {
    id: 'evt-04',
    timestamp: '17:21:06',
    agent: 'PQC Test Agent',
    type: 'tool_called',
    message: 'Invoked mcp-benchmark:run_liboqs_bench (100 iterations, timing resolution: 1ns)',
    payload: { algorithms: ['ECDSA', 'ML-DSA', 'SLH-DSA', 'Falcon'] },
  },
  {
    id: 'evt-05',
    timestamp: '17:21:07',
    agent: 'Verification Agent',
    type: 'agent_started',
    message: 'Executing 4-scenario tamper verification suite on generated keypairs.',
  },
  {
    id: 'evt-06',
    timestamp: '17:21:08',
    agent: 'Verification Agent',
    type: 'tool_called',
    message: 'Invoked mcp-crypto-test:tamper_matrix_verify (Bit-flip injection)',
    payload: { tamperDetectionRate: '100%' },
  },
  {
    id: 'evt-07',
    timestamp: '17:21:09',
    agent: 'Decision Engine',
    type: 'agent_started',
    message: 'Triage classifier computing risk coefficients: (algorithm_weight x exposure x lifetime x confidence).',
  },
  {
    id: 'evt-08',
    timestamp: '17:21:09',
    agent: 'Decision Engine',
    type: 'agent_finished',
    message: 'Decision rendered in 18.4ms: Recommended primary target is ML-DSA (FIPS 204).',
    payload: { latencyMs: 18.4, recommendation: 'ML-DSA' },
  },
  {
    id: 'evt-09',
    timestamp: '17:21:10',
    agent: 'Report Agent',
    type: 'agent_finished',
    message: 'Canonical JSON report assembled. SHA-256 computed: 0x9f4a...8b12. Ready for blockchain anchoring.',
  },
];

export const MOCK_MCP_LOGS: MCPCallLog[] = [
  {
    id: 'mcp-call-1',
    server: 'mcp-code-analysis',
    tool: 'scan_solidity_signatures',
    arguments: { path: 'contracts/', patterns: ['ecrecover', 'secp256k1', 'ECDSA'] },
    durationMs: 44,
    status: 'SUCCESS',
    timestamp: '17:21:03',
    allowedPathChecked: true,
  },
  {
    id: 'mcp-call-2',
    server: 'mcp-crypto-test',
    tool: 'execute_tamper_suite',
    arguments: { algorithms: ['ML-DSA', 'Falcon', 'SLH-DSA'], iterations: 100 },
    durationMs: 82,
    status: 'SUCCESS',
    timestamp: '17:21:06',
    allowedPathChecked: true,
  },
  {
    id: 'mcp-call-3',
    server: 'mcp-benchmark',
    tool: 'measure_perf_counter',
    arguments: { msgSize: 256, warmupRuns: 10 },
    durationMs: 120,
    status: 'SUCCESS',
    timestamp: '17:21:07',
    allowedPathChecked: true,
  },
  {
    id: 'mcp-call-4',
    server: 'mcp-blockchain',
    tool: 'anchor_report_hash',
    arguments: { contract: '0x5FbDB2315678afecb367f032d93F642f64180aa3', hash: '0x9f4a3e21c...' },
    durationMs: 18,
    status: 'SUCCESS',
    timestamp: '17:21:10',
    allowedPathChecked: true,
  },
];

export const MOCK_CANONICAL_REPORT: Report = {
  reportId: 'QC-REP-2024-8841',
  timestamp: new Date().toISOString(),
  targetApp: 'ERC-20 Token Wallet & Relayer',
  appType: 'Token Wallet',
  summary: {
    totalFilesScanned: 14,
    linesOfCode: 1840,
    vulnerablePatternsFound: 5,
    quantumRiskScore: 88, // out of 100
  },
  findings: MOCK_FINDINGS,
  benchmarks: MOCK_BENCHMARKS,
  verification: MOCK_VERIFICATION,
  decision: {
    latencyMs: 18.4,
    model: 'System-One Rule Engine',
    riskScore: 88.5,
    recommendedAlgorithm: 'ML-DSA',
    rationale: 'Balanced general use with FIPS 204 standardization status. Provides 128-bit post-quantum security with manageable 2.4KB signature overhead for EVM transaction relayers.',
    factors: {
      signatureLifetime: 'Long-term financial custody (> 5 years)',
      gasConstraint: 'Moderate (L2 / Arbitrum / Optimism target)',
      securityPriority: 'High (NIST FIPS 204 finalized compliance)',
    }
  },
  anchoredOnChain: true,
  blockchainAnchor: {
    chain: 'Anvil Localhost',
    contractAddress: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    transactionHash: '0x7e44a956d68b200b396b7972740fc601b65825ee58f121e491295b28d71249b1',
    blockNumber: 42,
    reportCanonicalHash: '0x9f4a3e21cb7596bcf29188d30e8446522c0ffbd6118bfa693521b44ecb998b12',
    anchoredAt: '2024-11-20T14:32:00Z',
    submitterAddress: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
  }
};

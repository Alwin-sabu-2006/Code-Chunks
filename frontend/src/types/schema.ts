/**
 * Q-Chain Shared Schema Definitions
 * Shared between Member 1 (Crypto), Member 2 (AI/Agents), Member 3 (Backend), Member 4 (Blockchain), Member 5 (Frontend)
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Finding {
  id: string;
  file: string;
  line: number;
  codeSnippet: string;
  algorithm: 'secp256k1' | 'ECDSA' | 'RSA' | 'ed25519' | 'ecrecover' | 'keccak256_sign';
  context: 'key_generation' | 'transaction_signing' | 'signature_verification' | 'key_exchange';
  quantumRisk: string;
  shorsImpact: string;
  confidenceScore: number; // 0.0 - 1.0
  severity: Severity;
  recommendedPqc: 'ML-DSA' | 'SLH-DSA' | 'Falcon';
  explanation: string;
}

export interface AlgorithmMetrics {
  name: 'ECDSA (secp256k1)' | 'ML-DSA (FIPS 204)' | 'SLH-DSA (FIPS 205)' | 'Falcon (FN-DSA)';
  securityLevel: string;
  isQuantumSafe: boolean;
  publicKeySize: number; // bytes
  signatureSize: number; // bytes
  keygenTimeUs: number; // microseconds
  signTimeUs: number; // microseconds
  verifyTimeUs: number; // microseconds
  gasEstimateUnits: number; // Ethereum/EVM gas units
  standardizationStatus: string;
  tradeoffSummary: string;
}

export interface TamperTestScenario {
  scenario: 'Valid Signature' | 'Flipped Message Bit' | 'Flipped Signature Bit' | 'Wrong Public Key';
  expectedResult: 'PASS' | 'FAIL';
  actualResult: 'PASS' | 'FAIL';
  passed: boolean;
  tamperDetected: boolean;
  details: string;
}

export interface AlgorithmVerificationMatrix {
  algorithm: string;
  scenarios: TamperTestScenario[];
  tamperDetectionRate: number; // percentage, e.g. 100%
}

export interface VerificationResult {
  timestamp: string;
  matrices: AlgorithmVerificationMatrix[];
  overallTamperDetectionRate: number;
  testIterations: number;
}

export interface DecisionEngineResult {
  latencyMs: number;
  model: 'System-One Rule Engine' | 'Decision Classifier';
  riskScore: number; // algorithm_weight x exposure x lifetime x confidence
  recommendedAlgorithm: 'ML-DSA' | 'SLH-DSA' | 'Falcon';
  rationale: string;
  factors: {
    signatureLifetime: string;
    gasConstraint: string;
    securityPriority: string;
  };
}

export interface Report {
  reportId: string;
  timestamp: string;
  targetApp: string;
  appType: 'Token Wallet' | 'Voting dApp' | 'Multisig' | 'Custom Upload';
  summary: {
    totalFilesScanned: number;
    linesOfCode: number;
    vulnerablePatternsFound: number;
    quantumRiskScore: number;
  };
  findings: Finding[];
  benchmarks: AlgorithmMetrics[];
  verification: VerificationResult;
  decision: DecisionEngineResult;
  anchoredOnChain: boolean;
  blockchainAnchor?: {
    chain: 'Anvil Localhost' | 'Sepolia Ethereum';
    contractAddress: string;
    transactionHash: string;
    blockNumber: number;
    reportCanonicalHash: string; // SHA-256
    anchoredAt: string;
    submitterAddress: string;
  };
}

export interface MCPCallLog {
  id: string;
  server: 'mcp-code-analysis' | 'mcp-crypto-test' | 'mcp-benchmark' | 'mcp-blockchain';
  tool: string;
  arguments: Record<string, any>;
  durationMs: number;
  status: 'SUCCESS' | 'ERROR';
  timestamp: string;
  allowedPathChecked: boolean;
}

export interface AgentEvent {
  id: string;
  timestamp: string;
  agent: 'Cryptographic Analysis Agent' | 'PQC Test Agent' | 'Verification Agent' | 'Decision Engine' | 'Report Agent';
  type: 'agent_started' | 'tool_called' | 'agent_progress' | 'agent_finished';
  message: string;
  payload?: any;
}

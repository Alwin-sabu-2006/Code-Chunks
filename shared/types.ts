/**
 * Q-Chain Shared TypeScript Types
 * ===============================
 * Automatically synchronized with shared/models.py
 * For Member 5 (Frontend, Voice and Demo Lead) to use directly in React/Next.js dashboard.
 */

export type QuantumRiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type CryptoContext =
  | 'key_generation'
  | 'signing'
  | 'verification'
  | 'hash_and_sign'
  | 'general';

export type AlgorithmCategory = 'classical' | 'post_quantum' | 'hybrid';

export type AgentEventType =
  | 'agent_started'
  | 'tool_called'
  | 'tool_completed'
  | 'agent_finished'
  | 'decision_made'
  | 'error'
  | 'log';

export type ScanStatus =
  | 'queued'
  | 'scanning'
  | 'benchmarking'
  | 'verifying'
  | 'deciding'
  | 'reporting'
  | 'completed'
  | 'failed';

export type TamperScenarioType =
  | 'valid_signature'
  | 'flipped_bit_message'
  | 'flipped_bit_signature'
  | 'wrong_public_key';

export interface Finding {
  id: string;
  file: string;
  line: number;
  algorithm: string;
  context: CryptoContext;
  quantum_risk: QuantumRiskLevel;
  confidence: number;
  code_snippet: string;
  explanation?: string;
  suggested_replacement?: string;
}

export interface BenchmarkMetrics {
  mean_ns: number;
  std_dev_ns: number;
  iterations: number;
  mean_us?: number;
}

export interface BenchmarkResult {
  algorithm: string;
  category: AlgorithmCategory;
  public_key_size_bytes: number;
  signature_size_bytes: number;
  message_size_bytes: number;
  keygen_metrics: BenchmarkMetrics;
  sign_metrics: BenchmarkMetrics;
  verify_metrics: BenchmarkMetrics;
  estimated_onchain_gas?: number;
  storage_overhead_ratio?: number;
}

export interface TamperScenarioResult {
  scenario: TamperScenarioType;
  description: string;
  expected_pass: boolean;
  actual_pass: boolean;
  test_passed: boolean;
  details?: string;
}

export interface VerificationResult {
  algorithm: string;
  scenarios: TamperScenarioResult[];
  tamper_detection_rate: number;
  all_tests_passed: boolean;
}

export interface DecisionResult {
  ranked_findings: Finding[];
  overall_risk_score: number;
  recommended_algorithm: string;
  recommendation_rationale: string;
  decision_latency_ms: number;
  rules_applied: string[];
}

export interface AnchorRecord {
  report_hash: string;
  tx_hash?: string;
  submitter?: string;
  timestamp: number;
  block_number?: number;
  network: string;
  status: 'anchored' | 'pending' | 'failed' | 'unanchored';
}

export interface Report {
  report_id: string;
  title: string;
  timestamp: string;
  target_app_name: string;
  target_app_path: string;
  tool_versions: Record<string, string>;
  findings: Finding[];
  benchmarks: BenchmarkResult[];
  verification_matrix: VerificationResult[];
  decision: DecisionResult;
  canonical_hash?: string;
  anchor_record?: AnchorRecord;
  pqc_signature?: string;
  pqc_public_key?: string;
}

export interface AgentEvent {
  event_id: string;
  timestamp: string;
  scan_id: string;
  agent_name: string;
  event_type: AgentEventType;
  message: string;
  data?: Record<string, any>;
}

export interface McpCallLog {
  call_id: string;
  timestamp: string;
  scan_id?: string;
  server_name: string;
  tool_name: string;
  arguments: Record<string, any>;
  result_summary?: string;
  duration_ms: number;
  status: 'success' | 'error';
  error_message?: string;
}

export interface ScanStartRequest {
  sample_app_id?: string;
  folder_path?: string;
  enable_llm_explanations?: boolean;
}

export interface ScanStartResponse {
  scan_id: string;
  status: ScanStatus;
  target_app_name: string;
  created_at: string;
  websocket_url: string;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: ScanStatus;
  progress_percentage: number;
  current_agent?: string;
  created_at: string;
  updated_at: string;
  error?: string;
}

export interface VerifyHashResponse {
  report_hash: string;
  computed_hash?: string;
  match_status: 'MATCH' | 'TAMPERED' | 'NOT_FOUND';
  is_anchored: boolean;
  record?: AnchorRecord;
  verification_message: string;
}

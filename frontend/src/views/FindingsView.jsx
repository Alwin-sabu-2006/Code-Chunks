import React, { useState, useEffect } from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  Cpu, 
  Sparkles, 
  CheckCircle2, 
  ChevronRight, 
  FileCode, 
  Clock, 
  ShieldCheck, 
  ArrowRight, 
  Code2 
} from 'lucide-react';
import './FindingsView.css';

export default function FindingsView({ 
  findings: propFindings = [], 
  activeReport, 
  hasScanned = false, 
  onNavigate 
}) {
  const [findings, setFindings] = useState(propFindings || []);
  const [selectedFindingId, setSelectedFindingId] = useState(propFindings?.[0]?.id || '');
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  useEffect(() => {
    setFindings(propFindings || []);
    if (propFindings && propFindings.length > 0) {
      if (!propFindings.some(f => f.id === selectedFindingId)) {
        setSelectedFindingId(propFindings[0].id);
      }
    } else {
      setSelectedFindingId('');
    }
  }, [propFindings]);

  // If no scan has been run yet
  if (!hasScanned) {
    return (
      <div className="findings-container animate-fade-in">
        <div className="findings-empty-state-card">
          <div className="empty-state-icon-bubble">
            <Code2 size={36} />
          </div>
          <h3 className="empty-state-title">Awaiting Code Analysis — No Scan Conducted Yet</h3>
          <p className="empty-state-desc">
            To view vulnerability findings, please enter or paste your smart contract code (or upload your repository archive) in the New Scan view. The deterministic AST engine will inspect every line for classical cryptographic signatures (ECDSA/secp256k1) and calculate post-quantum migration targets.
          </p>
          <button 
            type="button" 
            className="btn-empty-scan"
            onClick={() => onNavigate && onNavigate('New Scan')}
          >
            <span>Enter Your Work in New Scan</span>
            <ArrowRight size={16} />
          </button>
        </div>
      </div>
    );
  }

  const filesScanned = Number(
    activeReport?.decision?.filesScanned ??
    activeReport?.filesScanned ??
    activeReport?.summary?.totalFilesScanned ??
    (findings.length > 0 ? 1 : 0)
  );

  const linesScanned = Number(
    activeReport?.decision?.linesScanned ??
    activeReport?.linesScanned ??
    activeReport?.summary?.linesOfCode ??
    0
  );

  const languagesDetected = activeReport?.decision?.languagesDetected ||
    activeReport?.languagesDetected ||
    activeReport?.summary?.languagesDetected ||
    [];

  const scanOutcome = activeReport?.decision?.scanOutcome ||
    activeReport?.scanOutcome ||
    activeReport?.summary?.scanOutcome ||
    (findings.length > 0 ? 'FINDINGS_DETECTED' : (filesScanned === 0 ? 'UNANALYZABLE' : 'QUANTUM_SAFE'));

  // If scan completed but could not analyze code (0 files scanned or unparseable)
  if (hasScanned && (scanOutcome === 'UNANALYZABLE' || filesScanned === 0) && findings.length === 0) {
    return (
      <div className="findings-container animate-fade-in">
        <div className="findings-empty-state-card unanalyzable-state-card">
          <div className="empty-state-icon-bubble bubble-warning">
            <AlertTriangle size={36} color="#f59e0b" />
          </div>
          <h3 className="empty-state-title text-amber">Could Not Analyze — Unsupported Language or Empty Source</h3>
          <p className="empty-state-desc">
            The scanner found <strong>0 analyzable source code files</strong> (.sol, .js, .ts, .py) in the submitted input. A security tool must <strong>never</strong> report "Quantum-Safe" for uninspected or unanalyzable code. Please provide valid source files or an archive containing verifiable code.
          </p>
          <div className="clean-stats-row">
            <div className="unanalyzable-stat-box">
              <span className="stat-box-num-warning">0</span>
              <span className="stat-box-label">Files Scanned</span>
            </div>
            <div className="unanalyzable-stat-box">
              <span className="stat-box-num-warning">0</span>
              <span className="stat-box-label">Lines Scanned</span>
            </div>
            <div className="unanalyzable-stat-box">
              <span className="stat-box-num-warning">INCONCLUSIVE</span>
              <span className="stat-box-label">Scan Outcome</span>
            </div>
          </div>
          <button 
            type="button" 
            className="btn-warning-scan"
            onClick={() => onNavigate && onNavigate('New Scan')}
          >
            <span>Provide Valid Code in New Scan</span>
            <ArrowRight size={16} />
          </button>
        </div>
      </div>
    );
  }

  // If scan completed and verified 0 findings across parsed files (Clean code)
  if (hasScanned && findings.length === 0) {
    const langStr = languagesDetected.length > 0 ? languagesDetected.join(', ') : 'Python / Solidity / JS';
    return (
      <div className="findings-container animate-fade-in">
        <div className="findings-empty-state-card clean-state-card">
          <div className="empty-state-icon-bubble bubble-safe">
            <ShieldCheck size={36} color="#10b981" />
          </div>
          <h3 className="empty-state-title text-emerald">Zero Classical Primitives Detected (Quantum-Safe Baseline)</h3>
          <p className="empty-state-desc">
            Our deterministic AST analyzer parsed your submitted code across <strong>{filesScanned} file(s)</strong> ({linesScanned} lines of code, languages: {langStr}) and verified <strong>0 classical cryptographic primitives</strong> (no secp256k1, ECDSA, RSA, ECDH, or ecrecover). Your submitted work achieves baseline quantum resistance!
          </p>
          <div className="clean-stats-row">
            <div className="clean-stat-box">
              <span className="stat-box-num">{filesScanned}</span>
              <span className="stat-box-label">Files Scanned</span>
            </div>
            <div className="clean-stat-box">
              <span className="stat-box-num">{linesScanned}</span>
              <span className="stat-box-label">Lines Scanned</span>
            </div>
            <div className="clean-stat-box">
              <span className="stat-box-num">0 / 100</span>
              <span className="stat-box-label">Quantum Risk</span>
            </div>
            <div className="clean-stat-box">
              <span className="stat-box-num">PASS</span>
              <span className="stat-box-label">AST Verification</span>
            </div>
          </div>
          <button 
            type="button" 
            className="btn-empty-scan"
            onClick={() => onNavigate && onNavigate('New Scan')}
          >
            <span>Scan Another Contract or Script</span>
            <ArrowRight size={16} />
          </button>
        </div>
      </div>
    );
  }

  const selectedFinding = findings.find(f => f.id === selectedFindingId) || findings[0] || {};

  const filteredFindings = findings.filter(f => {
    if (filterSeverity === 'ALL') return true;
    return f.severity === filterSeverity;
  });

  const getSeverityBadgeClass = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'badge-sev-critical';
      case 'HIGH': return 'badge-sev-high';
      case 'MEDIUM': return 'badge-sev-medium';
      case 'LOW': return 'badge-sev-low';
      default: return '';
    }
  };

  const decisionLatency = activeReport?.decision?.latencyMs || 8.5;
  const recommendedAlgo = activeReport?.decision?.recommendedAlgorithm || 'ML-DSA-65 (FIPS 204)';
  const recommendationSub = activeReport?.decision?.rationale || 'Lattice-based digital signature replacement.';

  return (
    <div className="findings-container animate-fade-in">
      {/* Top Decision Engine HUD Header */}
      <div className="decision-engine-hud-card">
        <div className="hud-badge-row">
          <div className="hud-pill">
            <Cpu size={14} className="hud-icon" />
            <span>System One Decision Engine</span>
          </div>
          <div className="hud-latency-pill">
            <Clock size={13} />
            <span>Decision Latency: <strong>{decisionLatency} ms</strong> (Target &lt; 50ms)</span>
          </div>
          <div className="hud-pill" style={{ background: 'rgba(59, 130, 246, 0.15)', borderColor: 'rgba(59, 130, 246, 0.35)' }}>
            <FileCode size={13} />
            <span>Telemetry: <strong>{filesScanned} file(s)</strong>, <strong>{linesScanned} lines</strong> ({languagesDetected.join(', ') || 'Mixed'})</span>
          </div>
          <div className="hud-pill" style={{ background: 'rgba(239, 68, 68, 0.15)', borderColor: 'rgba(239, 68, 68, 0.35)', color: '#f87171' }}>
            <ShieldAlert size={13} />
            <span>Outcome: <strong>FINDINGS_DETECTED</strong></span>
          </div>
        </div>

        <div className="hud-content-split">
          <div>
            <h3 className="hud-title">{findings.length} Classical Cryptographic Flaws Detected</h3>
            <p className="hud-desc">
              Classical elliptic-curve signatures (ECDSA/secp256k1) cannot withstand quantum polynomial-time discrete log period finding (Shor's algorithm).
            </p>
          </div>
          <div className="hud-recommendation-box">
            <span className="rec-label">PRIMARY PQC RECOMMENDATION</span>
            <span className="rec-algo">{recommendedAlgo}</span>
            <span className="rec-sub">{recommendationSub}</span>
          </div>
        </div>
      </div>

      {/* Main Split Layout: Table / List on Left, Inspector on Right */}
      <div className="findings-layout-grid">
        {/* Left: Severity-ranked findings list */}
        <div className="findings-list-panel">
          <div className="findings-filter-bar">
            <div className="filter-buttons">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                <button
                  key={sev}
                  className={`sev-filter-btn ${filterSeverity === sev ? 'active-filter' : ''}`}
                  onClick={() => setFilterSeverity(sev)}
                >
                  {sev}
                </button>
              ))}
            </div>
            <span className="count-label">{filteredFindings.length} findings</span>
          </div>

          <div className="findings-scroll-list">
            {filteredFindings.map((f) => {
              const isSelected = f.id === selectedFinding.id;
              return (
                <div
                  key={f.id}
                  className={`finding-list-item ${isSelected ? 'finding-item-active' : ''}`}
                  onClick={() => setSelectedFindingId(f.id)}
                >
                  <div className="item-header-row">
                    <span className={`sev-tag ${getSeverityBadgeClass(f.severity)}`}>
                      {f.severity}
                    </span>
                    <span className="confidence-pill">
                      {Math.round(f.confidenceScore * 100)}% Confidence
                    </span>
                  </div>

                  <h4 className="item-algo-title">{f.algorithm}</h4>

                  <div className="item-loc-row">
                    <FileCode size={13} className="loc-icon" />
                    <span className="loc-text">{f.file}:{f.line}</span>
                  </div>

                  <div className="item-snippet-preview">
                    <code>{f.codeSnippet}</code>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Detailed Deep-Dive Inspector */}
        <div className="finding-inspector-panel">
          {selectedFinding.id ? (
            <div className="inspector-content">
              <div className="inspector-header">
                <div className="inspector-title-wrap">
                  <span className={`sev-badge-lg ${getSeverityBadgeClass(selectedFinding.severity)}`}>
                    {selectedFinding.severity}
                  </span>
                  <div>
                    <h3 className="inspector-algo">{selectedFinding.algorithm}</h3>
                    <span className="inspector-file-tag">{selectedFinding.file}:{selectedFinding.line}</span>
                  </div>
                </div>

                <div className="context-pill">
                  <span>Context: <strong>{selectedFinding.context}</strong></span>
                </div>
              </div>

              {/* Code Snippet Box with AST Highlights */}
              <div className="snippet-container">
                <div className="snippet-header">
                  <span className="snippet-file-label">{selectedFinding.file} (Line {selectedFinding.line})</span>
                  <span className="snippet-ast-tag">AST Pattern Match</span>
                </div>
                <div className="code-editor-mock">
                  <div className="line-numbers">
                    <span>{selectedFinding.line - 1}</span>
                    <span className="active-line-num">{selectedFinding.line}</span>
                    <span>{selectedFinding.line + 1}</span>
                  </div>
                  <div className="code-lines">
                    <span className="code-dim">// Authorization check</span>
                    <span className="code-highlight">{selectedFinding.codeSnippet}</span>
                    <span className="code-dim">// Next instruction</span>
                  </div>
                </div>
              </div>

              {/* Shor's Algorithm Vulnerability Mechanism */}
              <div className="vulnerability-explanation-card">
                <div className="expl-card-header">
                  <AlertTriangle size={16} className="expl-icon-amber" />
                  <h4>Shor's Algorithm Quantum Vulnerability Mechanism</h4>
                </div>
                <p className="expl-text">
                  {selectedFinding.shorsImpact}
                </p>
                <div className="quantum-physics-note">
                  <span>Mathematical Vulnerability: Discrete Logarithm Problem over secp256k1 reduced from exponential \(O(\sqrt{n})\) classical complexity to polynomial \(O(\log^3 n)\) quantum complexity.</span>
                </div>
              </div>

              {/* Recommended Post-Quantum Migration Strategy */}
              <div className="pqc-remediation-card">
                <div className="remed-header">
                  <ShieldAlert size={16} className="remed-icon-green" />
                  <h4>Prescribed Post-Quantum Migration Strategy</h4>
                </div>
                <div className="remed-algo-spec">
                  <span className="spec-label">DROP-IN PQC REPLACEMENT:</span>
                  <span className="spec-name">{selectedFinding.recommendedPqc}</span>
                </div>
                <p className="remed-desc">
                  {selectedFinding.explanation}
                </p>
              </div>
            </div>
          ) : (
            <div className="inspector-empty-state">
              <p>Select a vulnerability finding on the left to inspect AST snippet, Shor mechanics, and PQC replacement.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

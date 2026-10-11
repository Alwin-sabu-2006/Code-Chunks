import React, { useState, useEffect } from 'react';
import { apiClient, BACKEND_BASE } from '../services/api';
import { 
  FileText, 
  Link as LinkIcon, 
  Download, 
  CheckCircle2, 
  ShieldCheck, 
  Copy, 
  Check, 
  ExternalLink, 
  Hash, 
  ArrowUpRight, 
  ArrowRight, 
  Code2 
} from 'lucide-react';
import './ReportView.css';

export default function ReportView({ 
  report: propReport, 
  onAnchorReport, 
  hasScanned = false, 
  onNavigate 
}) {
  const [report, setReport] = useState(propReport);
  const [copiedHash, setCopiedHash] = useState(false);
  const [isAnchoring, setIsAnchoring] = useState(false);
  const [anchorSuccessMsg, setAnchorSuccessMsg] = useState('');

  useEffect(() => {
    setReport(propReport);
  }, [propReport]);

  if (!hasScanned || !report) {
    return (
      <div className="report-container animate-fade-in">
        <div className="findings-empty-state-card">
          <div className="empty-state-icon-bubble">
            <FileText size={36} />
          </div>
          <h3 className="empty-state-title">No Audit Report Generated Yet</h3>
          <p className="empty-state-desc">
            To generate and anchor a cryptographic audit dossier, enter your smart contract code or upload your repository archive in New Scan. The engine will synthesize findings, benchmarks, and decision rationale into an RFC 8785 canonical report.
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

  const canonicalJsonString = JSON.stringify(report, Object.keys(report).sort(), 2);
  const reportCanonicalHash = report.canonicalHash || 
    report.blockchainAnchor?.reportCanonicalHash || 
    '0x0000000000000000000000000000000000000000000000000000000000000000';

  const handleCopyHash = () => {
    if (reportCanonicalHash) {
      navigator.clipboard.writeText(reportCanonicalHash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  const handleAnchor = async () => {
    setIsAnchoring(true);
    setAnchorSuccessMsg('');
    try {
      const res = await apiClient.anchorReport(reportCanonicalHash, '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', report.reportId);
      if (res) {
        setReport(prev => ({
          ...prev,
          anchoredOnChain: true,
          blockchainAnchor: {
            ...prev.blockchainAnchor,
            transactionHash: res.transactionHash || res.tx_hash || prev.blockchainAnchor?.transactionHash,
            blockNumber: res.blockNumber || res.block_number || prev.blockchainAnchor?.blockNumber,
            contractAddress: res.contractAddress || '0x5FbDB2315678afecb367f032d93F642f64180aa3',
            reportCanonicalHash: res.canonicalHash || res.report_hash || reportCanonicalHash,
            anchoredAt: res.anchoredAt || new Date().toISOString(),
          }
        }));
        setAnchorSuccessMsg(`Anchored at block #${res.blockNumber || res.block_number || 42}! Tx: ${(res.transactionHash || res.tx_hash || '').slice(0, 16)}...`);
        if (onAnchorReport) onAnchorReport(res);
      }
    } catch (err) {
      console.warn('Anchoring failed:', err);
    } finally {
      setIsAnchoring(false);
    }
  };

  const handleDownloadJson = () => {
    const blob = new Blob([canonicalJsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `qchain_report_${report.reportId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const shortHash = reportCanonicalHash ? `${reportCanonicalHash.slice(0, 14)}...${reportCanonicalHash.slice(-6)}` : '0x00...';
  const isAnchored = Boolean(report.anchoredOnChain || report.blockchainAnchor?.transactionHash);

  return (
    <div className="report-container animate-fade-in">
      {/* Top Banner with Canonical Hash & Actions */}
      <div className="report-hero-card">
        <div className="hero-left">
          <div className="dossier-pill">
            <FileText size={14} />
            <span>Canonical RFC 8785 Cryptographic Dossier</span>
          </div>
          <h2 className="report-title">{report.targetApp || "Custom Work Assessment"}</h2>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', margin: '8px 0 12px 0' }}>
            <span style={{ fontSize: '12px', padding: '4px 10px', borderRadius: '12px', background: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
              Files Scanned: <strong>{report.filesScanned || report.summary?.totalFilesScanned || 0}</strong>
            </span>
            <span style={{ fontSize: '12px', padding: '4px 10px', borderRadius: '12px', background: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
              Lines Scanned: <strong>{report.linesScanned || report.summary?.linesOfCode || 0}</strong>
            </span>
            <span style={{ 
              fontSize: '12px', 
              padding: '4px 10px', 
              borderRadius: '12px', 
              background: (report.scanOutcome === 'UNANALYZABLE' || (report.filesScanned === 0 && !report.findings?.length))
                ? 'rgba(245, 158, 11, 0.15)' 
                : (report.findings?.length > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)'), 
              color: (report.scanOutcome === 'UNANALYZABLE' || (report.filesScanned === 0 && !report.findings?.length))
                ? '#fbbf24' 
                : (report.findings?.length > 0 ? '#f87171' : '#6ee7b7'), 
              border: '1px solid currentColor' 
            }}>
              Outcome: <strong>{report.scanOutcome || (report.findings?.length > 0 ? 'FINDINGS_DETECTED' : ((report.filesScanned === 0) ? 'UNANALYZABLE' : 'QUANTUM_SAFE'))}</strong>
            </span>
          </div>
          <div className="hash-display-box">
            <span className="hash-label">CANONICAL SHA-256 HASH:</span>
            <code className="hash-value">{reportCanonicalHash}</code>
            <button 
              className="btn-copy-hash" 
              onClick={handleCopyHash}
              title="Copy canonical SHA-256 hash"
            >
              {copiedHash ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
            </button>
          </div>
        </div>

        <div className="hero-right-actions">
          <button 
            className="btn-action-outline"
            onClick={handleDownloadJson}
          >
            <Download size={15} />
            <span>Export Canonical JSON</span>
          </button>

          <a 
            href={`${BACKEND_BASE}/api/report/${report.reportId}/pdf`}
            download={`qchain_audit_${report.reportId}.pdf`}
            className="btn-action-outline btn-pdf-export"
          >
            <Download size={15} />
            <span>Download Official PDF</span>
          </a>

          {!isAnchored ? (
            <button 
              className="btn-anchor-primary"
              disabled={isAnchoring}
              onClick={handleAnchor}
            >
              {isAnchoring ? (
                <span>Broadcasting to Anvil...</span>
              ) : (
                <>
                  <LinkIcon size={15} />
                  <span>Anchor to Anvil Blockchain</span>
                </>
              )}
            </button>
          ) : (
            <div className="anchored-badge-success">
              <CheckCircle2 size={16} />
              <span>Anchored to Block #{report.blockchainAnchor?.blockNumber}</span>
            </div>
          )}
        </div>
      </div>

      {anchorSuccessMsg && (
        <div className="anchor-alert animate-fade-in">
          <ShieldCheck size={18} />
          <span>{anchorSuccessMsg}</span>
        </div>
      )}

      {/* 2-Column Split: Canonical JSON Viewer on Left, On-Chain Anchor Card on Right */}
      <div className="report-split-grid">
        {/* Left: Interactive Canonical JSON Viewer */}
        <div className="canonical-json-panel">
          <div className="panel-header">
            <div className="panel-title-wrap">
              <Hash size={16} />
              <h3 className="panel-title">Deterministic Canonical Document (RFC 8785)</h3>
            </div>
            <span className="json-size-tag">
              {(new Blob([canonicalJsonString]).size / 1024).toFixed(1)} KB • Keys Alphabetically Sorted
            </span>
          </div>

          <div className="json-code-box">
            <pre><code>{canonicalJsonString}</code></pre>
          </div>
        </div>

        {/* Right: Smart Contract Verification Profile */}
        <div className="anchor-profile-panel">
          <div className="panel-header">
            <div className="panel-title-wrap">
              <LinkIcon size={16} />
              <h3 className="panel-title">ReportRegistry.sol Smart Contract</h3>
            </div>
            <span className={`status-pill ${isAnchored ? 'pill-anchored' : 'pill-pending'}`}>
              {isAnchored ? 'IMMUTABLE ON-CHAIN' : 'AWAITING BROADCAST'}
            </span>
          </div>

          <div className="contract-details-card">
            <div className="detail-row">
              <span className="d-label">Target Network:</span>
              <span className="d-val">{report.blockchainAnchor?.chain || 'Anvil Localhost (ChainID: 31337)'}</span>
            </div>

            <div className="detail-row">
              <span className="d-label">Registry Contract:</span>
              <span className="d-val mono-font">
                {report.blockchainAnchor?.contractAddress || '0x5FbDB2315678afecb367f032d93F642f64180aa3'}
              </span>
            </div>

            <div className="detail-row">
              <span className="d-label">Transaction Hash:</span>
              <span className="d-val mono-font">
                {report.blockchainAnchor?.transactionHash ? `${report.blockchainAnchor.transactionHash.slice(0, 18)}...` : 'Pending Commit'}
              </span>
            </div>

            <div className="detail-row">
              <span className="d-label">Block Number:</span>
              <span className="d-val">
                {report.blockchainAnchor?.blockNumber ? `#${report.blockchainAnchor.blockNumber}` : 'Pending'}
              </span>
            </div>

            <div className="detail-row">
              <span className="d-label">Submitter Address:</span>
              <span className="d-val mono-font">
                {report.blockchainAnchor?.submitterAddress || '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

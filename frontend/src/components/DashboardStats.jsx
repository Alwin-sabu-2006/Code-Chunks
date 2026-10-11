import React from 'react';
import { ArrowUpRight, ShieldAlert, Cpu, Link as LinkIcon, CheckCircle2, Lock } from 'lucide-react';
import './DashboardStats.css';

export default function DashboardStats({ onCardClick, activeReport, anchorRecord, hasScanned }) {
  const filesScanned = Number(
    activeReport?.decision?.filesScanned ??
    activeReport?.filesScanned ??
    activeReport?.summary?.totalFilesScanned ??
    ((activeReport?.findings?.length || 0) > 0 ? 1 : 0)
  );

  const linesScanned = Number(
    activeReport?.decision?.linesScanned ??
    activeReport?.linesScanned ??
    activeReport?.summary?.linesOfCode ??
    0
  );

  const scanOutcome = activeReport?.decision?.scanOutcome ||
    activeReport?.scanOutcome ||
    activeReport?.summary?.scanOutcome ||
    ((activeReport?.findings?.length || 0) > 0 ? 'FINDINGS_DETECTED' : (filesScanned === 0 ? 'UNANALYZABLE' : 'QUANTUM_SAFE'));

  const isUnanalyzable = hasScanned && (scanOutcome === 'UNANALYZABLE' || filesScanned === 0);
  const isClean = hasScanned && !isUnanalyzable && (activeReport?.findings?.length || 0) === 0;

  const rawRiskScore = activeReport?.summary?.quantumRiskScore ?? activeReport?.decision?.riskScore ?? 0;
  const riskScore = isUnanalyzable ? '--' : rawRiskScore;
  const flawsCount = isUnanalyzable ? 0 : (activeReport?.summary?.vulnerablePatternsFound ?? activeReport?.findings?.length ?? 0);
  const primaryPqc = isUnanalyzable
    ? 'Unanalyzable'
    : (activeReport?.decision?.recommendedAlgorithm || (hasScanned ? (isClean ? 'Quantum-Safe' : 'ML-DSA-65') : 'Pending Scan'));
  const blockNum = activeReport?.blockchainAnchor?.blockNumber || anchorRecord?.block_number;
  const chainName = activeReport?.blockchainAnchor?.chain || 'Anvil Localhost';

  const cards = [
    {
      id: 'risk',
      title: 'Quantum Risk Score',
      value: hasScanned ? (isUnanalyzable ? 'INCONCLUSIVE' : `${riskScore}/100`) : '-- / 100',
      trend: hasScanned 
        ? (isUnanalyzable ? 'Could Not Analyze (0 Files Parsed)' : (isClean ? `Safe Baseline (${filesScanned} files, ${linesScanned} lines clean)` : `${rawRiskScore >= 70 ? 'CRITICAL' : 'HIGH'} Exposure (Shor Algorithm)`))
        : 'Awaiting Code Entry & Calculation',
      isDark: true,
      icon: ShieldAlert,
      badgeText: hasScanned ? (isUnanalyzable ? 'Unanalyzable' : (isClean ? 'Quantum-Safe' : 'High Exposure')) : 'Awaiting Input',
    },
    {
      id: 'flaws',
      title: 'Classical Signatures Flagged',
      value: hasScanned ? (isUnanalyzable ? '0' : `${flawsCount}`) : '--',
      trend: hasScanned 
        ? (isUnanalyzable ? '0 files parsed — fail-closed security' : `${flawsCount} detected in AST analysis (${filesScanned} files, ${linesScanned} lines)`)
        : 'Enter code in New Scan to inspect',
      isDark: false,
      icon: Lock,
      badgeText: hasScanned ? (isUnanalyzable ? 'Unsupported / Empty' : 'Deterministic AST') : 'Pending Input',
    },
    {
      id: 'pqc',
      title: 'Primary PQC Target',
      value: hasScanned ? primaryPqc : 'Pending Scan',
      trend: isUnanalyzable
        ? 'Requires verifiable source files'
        : (hasScanned ? 'NIST FIPS 204/205 standardization' : 'Calculated upon work submission'),
      isDark: false,
      icon: Cpu,
      badgeText: isUnanalyzable ? 'Inconclusive' : 'NIST Standards',
    },
    {
      id: 'anchor',
      title: 'Blockchain Anchor',
      value: hasScanned && blockNum ? `Block #${blockNum}` : 'Unanchored',
      trend: hasScanned && blockNum ? `${chainName} • ReportRegistry` : 'Anchored on Anvil upon scan completion',
      isDark: false,
      icon: LinkIcon,
      badgeText: hasScanned && blockNum ? 'SHA-256 Verified' : 'Awaiting Scan',
    },
  ];

  return (
    <div className="stats-grid">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.id}
            className={`stat-card ${card.isDark ? 'stat-card-dark' : 'stat-card-light'}`}
            onClick={() => onCardClick && onCardClick(card.id)}
          >
            <div className="stat-card-header">
              <span className={`stat-title ${card.isDark ? 'text-white-subtle' : 'text-gray-subtle'}`}>
                {card.title}
              </span>
              <button className={`stat-arrow-btn ${card.isDark ? 'arrow-btn-dark' : 'arrow-btn-light'}`}>
                <ArrowUpRight size={16} />
              </button>
            </div>

            <div className="stat-value-wrap">
              <span className={`stat-value ${card.isDark ? 'value-dark' : 'value-light'}`}>
                {card.value}
              </span>
            </div>

            <div className="stat-card-footer">
              <div className={`stat-trend-pill ${card.isDark ? 'pill-dark' : 'pill-light'}`}>
                <Icon size={12} className="trend-icon" />
                <span>{card.trend}</span>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

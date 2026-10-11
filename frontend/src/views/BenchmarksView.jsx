import React, { useState, useEffect } from 'react';
import { MOCK_BENCHMARKS } from '../data/mockData';
import { apiClient } from '../services/api';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell, ScatterChart, Scatter, ZAxis 
} from 'recharts';
import { Shield, Zap, Database, Clock, Scale, Info, CheckCircle2, DollarSign, Calculator, Layers, RefreshCw } from 'lucide-react';
import './BenchmarksView.css';

export default function BenchmarksView({ benchmarks: propBenchmarks }) {
  const initialBenchmarks = (propBenchmarks && propBenchmarks.length > 0) ? propBenchmarks : MOCK_BENCHMARKS;
  const [benchmarks, setBenchmarks] = useState(initialBenchmarks);
  const [isRunningBench, setIsRunningBench] = useState(false);
  const [selectedMetric, setSelectedMetric] = useState('signatureSize');
  const [chartViewMode, setChartViewMode] = useState('bars'); // 'bars' | 'scatter'
  const [selectedSecurityLevel, setSelectedSecurityLevel] = useState('ALL');

  useEffect(() => {
    if (propBenchmarks && propBenchmarks.length > 0) {
      setBenchmarks(propBenchmarks);
    }
  }, [propBenchmarks]);

  // Interactive Gas Calculator State
  const [dailyTxVolume, setDailyTxVolume] = useState(10000); // 10,000 txs/day
  const [gasPriceGwei, setGasPriceGwei] = useState(25); // 25 Gwei
  const [ethPriceUsd, setEthPriceUsd] = useState(3200); // $3,200 per ETH

  const metricOptions = [
    { key: 'signatureSize', label: 'Signature Size (Bytes)', unit: 'bytes', desc: 'Critical for EVM calldata & storage costs' },
    { key: 'publicKeySize', label: 'Public Key Size (Bytes)', unit: 'bytes', desc: 'Footprint of account abstraction state' },
    { key: 'verifyTimeUs', label: 'Verification Latency (μs)', unit: 'μs', desc: 'Processing speed on validator nodes' },
    { key: 'gasEstimateUnits', label: 'Estimated EVM Gas', unit: 'gas', desc: 'Transaction execution cost on EVM L1/L2' },
  ];

  const currentOption = metricOptions.find(o => o.key === selectedMetric) || metricOptions[0];

  const handleRunLiveBenchmarks = async () => {
    setIsRunningBench(true);
    try {
      const results = await apiClient.runBenchmarks();
      if (results && results.length > 0) {
        setBenchmarks(results);
      }
    } catch (err) {
      console.warn('Live benchmark run failed:', err);
    } finally {
      setIsRunningBench(false);
    }
  };

  const filteredAlgos = benchmarks.filter(algo => {
    if (selectedSecurityLevel === 'ALL') return true;
    if (selectedSecurityLevel === 'PQC') return algo.isQuantumSafe;
    if (selectedSecurityLevel === 'NIST2') return algo.name.includes('ML-DSA');
    return true;
  });

  const chartData = filteredAlgos.map(b => ({
    name: b.name.split(' ')[0],
    fullName: b.name,
    value: b[selectedMetric],
    isQuantumSafe: b.isQuantumSafe,
    x: b.signatureSize,
    y: b.verifyTimeUs,
    z: b.gasEstimateUnits,
  }));

  const getBarColor = (entry) => {
    if (!entry.isQuantumSafe) return '#94a3b8';
    if (entry.name === 'ML-DSA' || entry.fullName?.includes('ML-DSA')) return '#10b981';
    if (entry.name === 'Falcon' || entry.fullName?.includes('Falcon')) return '#0d9488';
    return '#6366f1';
  };

  // Gas Cost Calculator Logic
  const calculateAnnualCost = (gasUnits) => {
    const totalGasDaily = gasUnits * dailyTxVolume;
    const dailyEth = (totalGasDaily * gasPriceGwei) / 1e9;
    const annualEth = dailyEth * 365;
    const annualUsd = annualEth * ethPriceUsd;
    return {
      annualEth: annualEth.toFixed(2),
      annualUsd: Math.round(annualUsd).toLocaleString(),
    };
  };

  return (
    <div className="benchmarks-container animate-fade-in">
      {/* Top Banner */}
      <div className="benchmarks-header-card">
        <div className="header-tags-row">
          <span className="nist-standard-tag">
            <Shield size={13} />
            <span>NIST PQC Standardization Benchmark</span>
          </span>
          <span className="liboqs-tag">liboqs 0.10.0 • In-Process Engine</span>
          <button 
            className="btn-run-bench-mini" 
            onClick={handleRunLiveBenchmarks}
            disabled={isRunningBench}
            style={{
              marginLeft: 'auto',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '4px 12px',
              borderRadius: '6px',
              backgroundColor: 'rgba(59, 130, 246, 0.15)',
              border: '1px solid rgba(59, 130, 246, 0.4)',
              color: '#60a5fa',
              cursor: isRunningBench ? 'not-allowed' : 'pointer',
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            <RefreshCw size={12} className={isRunningBench ? 'spin' : ''} />
            <span>{isRunningBench ? 'Benchmarking liboqs...' : 'Run Live Benchmark Harness'}</span>
          </button>
        </div>
        <h2 className="benchmarks-title">Post-Quantum Cryptography Comparative Tradeoffs</h2>
        <p className="benchmarks-sub">
          Comparing classical baseline ECDSA (secp256k1) against standardized NIST lattice and hash-based signature algorithms across signature footprint, computational latency, and blockchain gas constraints.
        </p>
      </div>

      {/* Chart Section */}
      <div className="benchmarks-chart-card">
        <div className="chart-header-row">
          <div>
            <h3 className="chart-title">{currentOption.label}</h3>
            <span className="chart-subtitle">{currentOption.desc}</span>
          </div>

          <div className="controls-right-group">
            <div className="view-mode-toggle">
              <button 
                className={`mode-btn ${chartViewMode === 'bars' ? 'active-mode' : ''}`}
                onClick={() => setChartViewMode('bars')}
              >
                Bar Comparison
              </button>
              <button 
                className={`mode-btn ${chartViewMode === 'scatter' ? 'active-mode' : ''}`}
                onClick={() => setChartViewMode('scatter')}
              >
                Tradeoff Scatter
              </button>
            </div>

            <div className="metric-select-wrap">
              <select 
                value={selectedMetric}
                onChange={(e) => setSelectedMetric(e.target.value)}
                className="metric-dropdown"
              >
                {metricOptions.map(opt => (
                  <option key={opt.key} value={opt.key}>{opt.label}</option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="level-filters-row">
          <span className="filter-label">Filter:</span>
          {['ALL', 'PQC', 'NIST2'].map((lvl) => (
            <button
              key={lvl}
              className={`lvl-pill-btn ${selectedSecurityLevel === lvl ? 'active-lvl' : ''}`}
              onClick={() => setSelectedSecurityLevel(lvl)}
            >
              {lvl === 'ALL' ? 'All Algorithms' : lvl === 'PQC' ? 'Post-Quantum Only' : 'NIST Level 2 (ML-DSA)'}
            </button>
          ))}
        </div>

        {/* Render Chart */}
        <div className="chart-viewport">
          <ResponsiveContainer width="100%" height={290}>
            {chartViewMode === 'bars' ? (
              <BarChart data={chartData} margin={{ top: 15, right: 20, left: 20, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="name" stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                <YAxis stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', borderRadius: 8, color: '#f8fafc' }}
                  formatter={(val) => [`${Number(val).toLocaleString()} ${currentOption.unit}`, currentOption.label]}
                  labelFormatter={(name) => `Algorithm: ${name}`}
                />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={getBarColor(entry)} />
                  ))}
                </Bar>
              </BarChart>
            ) : (
              <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis type="number" dataKey="x" name="Signature Size" unit=" bytes" stroke="#94a3b8" />
                <YAxis type="number" dataKey="y" name="Verification Time" unit=" μs" stroke="#94a3b8" />
                <ZAxis type="number" dataKey="z" range={[80, 400]} name="Gas" />
                <Tooltip cursor={{ strokeDasharray: '3 3' }} />
                <Scatter name="Algorithms" data={chartData} fill="#10b981" />
              </ScatterChart>
            )}
          </ResponsiveContainer>
        </div>
      </div>

      {/* Interactive Gas Calculator */}
      <div className="gas-calculator-card">
        <div className="calc-header">
          <div className="calc-title-group">
            <Calculator size={18} className="calc-icon" />
            <h3 className="calc-title">Interactive On-Chain Migration Gas Cost Calculator</h3>
          </div>
          <span className="calc-subtitle">Simulate EVM calldata overhead across Layer-1 and Rollups</span>
        </div>

        <div className="calc-inputs-grid">
          <div className="calc-input-block">
            <div className="input-label-row">
              <span className="input-label">Daily Transaction Volume</span>
              <span className="input-val-tag">{dailyTxVolume.toLocaleString()} txs/day</span>
            </div>
            <input 
              type="range" 
              min="1000" 
              max="100000" 
              step="1000"
              value={dailyTxVolume} 
              onChange={(e) => setDailyTxVolume(Number(e.target.value))}
              className="calc-range-input"
            />
          </div>

          <div className="calc-input-block">
            <div className="input-label-row">
              <span className="input-label">Average Gas Price</span>
              <span className="input-val-tag">{gasPriceGwei} Gwei</span>
            </div>
            <input 
              type="range" 
              min="5" 
              max="100" 
              step="5"
              value={gasPriceGwei} 
              onChange={(e) => setGasPriceGwei(Number(e.target.value))}
              className="calc-range-input"
            />
          </div>

          <div className="calc-input-block">
            <div className="input-label-row">
              <span className="input-label">ETH / USD Price</span>
              <span className="input-val-tag">${ethPriceUsd.toLocaleString()}</span>
            </div>
            <input 
              type="range" 
              min="1000" 
              max="8000" 
              step="200"
              value={ethPriceUsd} 
              onChange={(e) => setEthPriceUsd(Number(e.target.value))}
              className="calc-range-input"
            />
          </div>
        </div>

        {/* Real-time Calculation Comparison Cards */}
        <div className="calc-results-row">
          {benchmarks.map((algo) => {
            const cost = calculateAnnualCost(algo.gasEstimateUnits);
            return (
              <div key={algo.name} className="calc-result-card">
                <span className="algo-header-name">{algo.name.split(' ')[0]}</span>
                <span className="gas-per-tx">{algo.gasEstimateUnits.toLocaleString()} gas / tx</span>
                <div className="cost-breakdown">
                  <span className="cost-annual-usd">${cost.annualUsd} / yr</span>
                  <span className="cost-annual-eth">{cost.annualEth} ETH / yr</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Algorithm Matrix Cards */}
      <div className="algo-cards-grid">
        {filteredAlgos.map((algo) => (
          <div key={algo.name} className={`algo-card ${algo.isQuantumSafe ? 'algo-quantum-safe' : 'algo-legacy'}`}>
            <div className="algo-card-top">
              <span className={`safety-status-pill ${algo.isQuantumSafe ? 'pill-safe' : 'pill-legacy'}`}>
                {algo.isQuantumSafe ? 'Quantum-Safe' : 'Legacy ECDSA'}
              </span>
              <span className="algo-level">{algo.securityLevel}</span>
            </div>

            <h4 className="algo-name">{algo.name}</h4>
            <p className="algo-status-text">{algo.standardizationStatus}</p>

            <div className="algo-metrics-specs">
              <div className="spec-row">
                <span className="spec-label">Signature Size</span>
                <strong className="spec-val">{algo.signatureSize} bytes</strong>
              </div>
              <div className="spec-row">
                <span className="spec-label">Public Key</span>
                <strong className="spec-val">{algo.publicKeySize} bytes</strong>
              </div>
              <div className="spec-row">
                <span className="spec-label">Verify Speed</span>
                <strong className="spec-val">{algo.verifyTimeUs} μs</strong>
              </div>
              <div className="spec-row">
                <span className="spec-label">Est. EVM Gas</span>
                <strong className="spec-val">{algo.gasEstimateUnits.toLocaleString()} units</strong>
              </div>
            </div>

            <p className="algo-tradeoff-summary">{algo.tradeoffSummary}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

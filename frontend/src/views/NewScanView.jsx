import React, { useState, useEffect } from 'react';
import { SAMPLE_APPS } from '../data/mockData';
import { apiClient } from '../services/api';
import { 
  ShieldCheck, 
  UploadCloud, 
  Cpu, 
  Play, 
  CheckCircle2, 
  FileCode, 
  Lock, 
  ArrowRight, 
  Zap, 
  Code, 
  FileUp, 
  Sparkles, 
  Trash2, 
  Copy, 
  Check, 
  AlertCircle 
} from 'lucide-react';
import './NewScanView.css';

const SAMPLE_VULNERABLE_SOLIDITY = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TokenVault
 * @notice Vault relying on classical ECDSA / secp256k1 signatures
 */
contract TokenVault {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public executedHashes;

    event Executed(address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // Vulnerable classical signature verification:
    // Shor's discrete log algorithm solves secp256k1 private keys from on-chain signatures
    function executeTransferWithSignature(
        address to,
        uint256 amount,
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(!executedHashes[messageHash], "Signature already executed");

        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\\x19Ethereum Signed Message:\\n32", messageHash)
        );

        // AST Scanner Flags ecrecover: Shor-vulnerable classical primitive
        address signer = ecrecover(ethSignedMessageHash, v, r, s);
        require(signer == owner, "Invalid ECDSA signature authorization");

        executedHashes[messageHash] = true;
        balances[to] += amount;
        emit Executed(to, amount);
    }
}`;

const SAMPLE_CLEAN_SOLIDITY = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PostQuantumStateVault
 * @notice Clean state vault with zero classical elliptic-curve signatures
 */
contract PostQuantumStateVault {
    address public immutable admin;
    bytes32 public rootStateHash;
    mapping(address => uint256) public balances;

    event StateCommitted(bytes32 indexed newRoot, uint256 timestamp);
    event Deposited(address indexed account, uint256 amount);

    constructor() {
        admin = msg.sender;
    }

    // 256-bit symmetric hash operations remain resistant to Grover's algorithm (128-bit quantum security)
    function commitRoot(bytes32 newRoot) external {
        require(msg.sender == admin, "Caller is not admin");
        rootStateHash = newRoot;
        emit StateCommitted(newRoot, block.timestamp);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
}`;

const SAMPLE_VULNERABLE_TS = `import { ethers } from "ethers";

/**
 * Off-chain dApp relayer authorizer using ethers.Wallet
 */
export async function signRelayTransaction(privateKey: string, recipient: string, amount: string) {
    // AST Flag: secp256k1 key generation vulnerable to Shor's algorithm
    const wallet = new ethers.Wallet(privateKey);
    
    const payloadHash = ethers.utils.solidityKeccak256(
        ["address", "uint256"],
        [recipient, amount]
    );

    // AST Flag: Classical ECDSA signMessage
    const signature = await wallet.signMessage(ethers.utils.arrayify(payloadHash));
    
    return {
        signer: wallet.address,
        payloadHash,
        signature
    };
}`;

export default function NewScanView({ onStartScan, isScanning, scanProgress }) {
  // Mode tabs: 'paste' (default), 'upload', 'samples'
  const [activeTab, setActiveTab] = useState('paste');
  
  // Paste Code State
  const [selectedLanguage, setSelectedLanguage] = useState('sol'); // 'sol' | 'ts' | 'py'
  const [customFilename, setCustomFilename] = useState('TokenVault.sol');
  const [codeContent, setCodeContent] = useState(SAMPLE_VULNERABLE_SOLIDITY);
  const [copySuccess, setCopySuccess] = useState(false);

  // Upload File State
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadedFileName, setUploadedFileName] = useState('');

  // Sample App State (Fallback / Reference)
  const [appsList, setAppsList] = useState(SAMPLE_APPS);
  const [selectedSampleId, setSelectedSampleId] = useState('token-wallet');

  // Input Validation Error
  const [validationError, setValidationError] = useState('');

  useEffect(() => {
    async function loadSamples() {
      const backendSamples = await apiClient.fetchSamples();
      if (backendSamples && backendSamples.length > 0) {
        const mapped = backendSamples.map(s => ({
          id: s.id.replace('_', '-'),
          backendId: s.id,
          name: s.name,
          type: s.id.includes('wallet') ? 'Token Wallet' : s.id.includes('voting') ? 'Voting dApp' : 'Multisig',
          description: s.description,
          filesCount: s.id.includes('wallet') ? 14 : s.id.includes('voting') ? 18 : 22,
          linesOfCode: s.id.includes('wallet') ? 1840 : s.id.includes('voting') ? 2450 : 3120,
          tags: ['Solidity', 'ECDSA', 'AST'],
        }));
        setAppsList(mapped);
      }
    }
    loadSamples();
  }, []);

  const handleLanguageChange = (lang) => {
    setSelectedLanguage(lang);
    if (lang === 'sol') {
      setCustomFilename('TokenVault.sol');
      if (!codeContent.trim() || codeContent === SAMPLE_VULNERABLE_TS) {
        setCodeContent(SAMPLE_VULNERABLE_SOLIDITY);
      }
    } else if (lang === 'ts') {
      setCustomFilename('RelayerSigner.ts');
      setCodeContent(SAMPLE_VULNERABLE_TS);
    } else if (lang === 'py') {
      setCustomFilename('verifier.py');
      setCodeContent("# Python cryptographic script\nimport hashlib\n\ndef verify_hash(data: bytes, expected_hash: str) -> bool:\n    return hashlib.sha256(data).hexdigest() == expected_hash\n");
    }
  };

  const handleFileUpload = (e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setUploadedFileName(file.name);
      setValidationError('');
    }
  };

  const handleLaunch = () => {
    setValidationError('');
    if (activeTab === 'paste') {
      if (!codeContent.trim()) {
        setValidationError('Please enter or paste your code before scanning.');
        return;
      }
      if (onStartScan) {
        const fname = customFilename.trim() || (selectedLanguage === 'sol' ? 'Contract.sol' : selectedLanguage === 'ts' ? 'index.ts' : 'script.py');
        onStartScan('custom_user_code', null, codeContent, fname);
      }
    } else if (activeTab === 'upload') {
      if (!selectedFile) {
        setValidationError('Please select or drop a file / archive (.sol, .ts, .py, .zip) to scan.');
        return;
      }
      if (onStartScan) {
        onStartScan('custom_upload', selectedFile, null, selectedFile.name);
      }
    } else if (activeTab === 'samples') {
      if (onStartScan) {
        onStartScan(selectedSampleId, null, null, null);
      }
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(codeContent);
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  return (
    <div className="new-scan-container animate-fade-in">
      {/* Header Banner */}
      <div className="scan-banner-card">
        <div className="scan-banner-content">
          <div className="badge-row">
            <span className="edge-privacy-pill">
              <Cpu size={14} className="pill-icon" />
              <span>Local Edge Engine • 0 External Egress</span>
            </span>
            <span className="nist-badge">NIST FIPS 204 & 205 Standards</span>
            <span className="evm-badge">EVM AST Scanner</span>
          </div>
          <h2 className="scan-banner-title">Enter Your Work &amp; Calculate Quantum Risk</h2>
          <p className="scan-banner-desc">
            Provide your Solidity smart contract, TypeScript Web3 script, or code repository. The multi-agent pipeline analyzes your work for classical signatures (ECDSA/secp256k1), computes real quantum risk scores, evaluates NIST post-quantum replacements (ML-DSA, Falcon), tests tamper resistance, and anchors verification on-chain.
          </p>
        </div>
      </div>

      {/* Main Work Entry Workspace */}
      <div className="work-entry-card">
        {/* Work Entry Mode Navigation */}
        <div className="entry-mode-tabs">
          <button 
            type="button"
            className={`entry-tab-btn ${activeTab === 'paste' ? 'tab-btn-active' : ''}`}
            onClick={() => { setActiveTab('paste'); setValidationError(''); }}
          >
            <Code size={16} />
            <span>Paste Your Code (Primary)</span>
            <span className="tab-pill-badge">Direct AST</span>
          </button>

          <button 
            type="button"
            className={`entry-tab-btn ${activeTab === 'upload' ? 'tab-btn-active' : ''}`}
            onClick={() => { setActiveTab('upload'); setValidationError(''); }}
          >
            <FileUp size={16} />
            <span>Upload File or Archive</span>
            <span className="tab-pill-badge">.sol / .zip</span>
          </button>

          <button 
            type="button"
            className={`entry-tab-btn ${activeTab === 'samples' ? 'tab-btn-active' : ''}`}
            onClick={() => { setActiveTab('samples'); setValidationError(''); }}
          >
            <Sparkles size={16} />
            <span>Test Bundled Demo (Optional)</span>
          </button>
        </div>

        {/* Validation Error Message */}
        {validationError && (
          <div className="entry-error-banner animate-fade-in">
            <AlertCircle size={16} />
            <span>{validationError}</span>
          </div>
        )}

        {/* TAB 1: PASTE CODE DIRECTLY */}
        {activeTab === 'paste' && (
          <div className="code-editor-panel animate-fade-in">
            {/* Editor Toolbar */}
            <div className="editor-toolbar">
              <div className="toolbar-left">
                <span className="toolbar-label">Language:</span>
                <div className="lang-selector-group">
                  <button 
                    type="button"
                    className={`lang-btn ${selectedLanguage === 'sol' ? 'lang-btn-active' : ''}`}
                    onClick={() => handleLanguageChange('sol')}
                  >
                    Solidity (.sol)
                  </button>
                  <button 
                    type="button"
                    className={`lang-btn ${selectedLanguage === 'ts' ? 'lang-btn-active' : ''}`}
                    onClick={() => handleLanguageChange('ts')}
                  >
                    TypeScript (.ts)
                  </button>
                  <button 
                    type="button"
                    className={`lang-btn ${selectedLanguage === 'py' ? 'lang-btn-active' : ''}`}
                    onClick={() => handleLanguageChange('py')}
                  >
                    Python (.py)
                  </button>
                </div>

                <div className="filename-input-wrap">
                  <span className="filename-prefix">File:</span>
                  <input 
                    type="text"
                    className="filename-input"
                    value={customFilename}
                    onChange={(e) => setCustomFilename(e.target.value)}
                    placeholder="Contract.sol"
                  />
                </div>
              </div>

              <div className="toolbar-right">
                <button 
                  type="button" 
                  className="quick-sample-btn"
                  title="Load example contract with ecrecover vulnerability"
                  onClick={() => {
                    setSelectedLanguage('sol');
                    setCustomFilename('VulnerableTokenVault.sol');
                    setCodeContent(SAMPLE_VULNERABLE_SOLIDITY);
                  }}
                >
                  <AlertCircle size={13} />
                  <span>Load Vulnerable Example</span>
                </button>

                <button 
                  type="button" 
                  className="quick-sample-btn sample-safe"
                  title="Load example contract with zero quantum flaws"
                  onClick={() => {
                    setSelectedLanguage('sol');
                    setCustomFilename('PostQuantumVault.sol');
                    setCodeContent(SAMPLE_CLEAN_SOLIDITY);
                  }}
                >
                  <CheckCircle2 size={13} />
                  <span>Load Clean Example</span>
                </button>

                <button 
                  type="button" 
                  className="toolbar-action-btn"
                  onClick={handleCopyCode}
                  title="Copy code to clipboard"
                >
                  {copySuccess ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                </button>

                <button 
                  type="button" 
                  className="toolbar-action-btn"
                  onClick={() => setCodeContent('')}
                  title="Clear code editor"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>

            {/* Monospace Code Editor Area */}
            <div className="editor-textarea-wrap">
              <textarea 
                className="code-textarea"
                value={codeContent}
                onChange={(e) => setCodeContent(e.target.value)}
                placeholder="Paste or write your smart contract code here..."
                rows={18}
                spellCheck={false}
              />
              <div className="editor-footer-info">
                <span>{codeContent.split('\n').length} lines • {codeContent.length} characters</span>
                <span className="editor-guide-pill">Real AST analysis scans every line</span>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: UPLOAD FILE OR ARCHIVE */}
        {activeTab === 'upload' && (
          <div className="upload-panel animate-fade-in">
            <div 
              className={`dropzone-box ${selectedFile ? 'dropzone-has-file' : ''}`}
              onClick={() => document.getElementById('archive-file-picker').click()}
            >
              <input 
                id="archive-file-picker"
                type="file"
                accept=".sol,.ts,.js,.py,.zip,.tar.gz,.tar"
                style={{ display: 'none' }}
                onChange={handleFileUpload}
              />

              <div className="dropzone-icon-circle">
                <UploadCloud size={32} />
              </div>

              {selectedFile ? (
                <div className="dropzone-file-details">
                  <h4 className="file-name-display">{selectedFile.name}</h4>
                  <p className="file-meta-display">
                    {(selectedFile.size / 1024).toFixed(1)} KB • Ready for AST Inspection &amp; Benchmark Harness
                  </p>
                  <button 
                    type="button" 
                    className="btn-replace-file"
                    onClick={(e) => {
                      e.stopPropagation();
                      document.getElementById('archive-file-picker').click();
                    }}
                  >
                    Choose Different File
                  </button>
                </div>
              ) : (
                <div className="dropzone-prompt">
                  <h4 className="dropzone-title">Click to Browse or Drag &amp; Drop Your File</h4>
                  <p className="dropzone-subtitle">
                    Supports individual smart contracts (<strong>.sol</strong>), Web3 scripts (<strong>.ts</strong>, <strong>.js</strong>, <strong>.py</strong>), or compressed archives (<strong>.zip</strong>, <strong>.tar.gz</strong>).
                  </p>
                  <span className="dropzone-browse-badge">Browse Local Storage</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: TEST BUNDLED DEMO SAMPLES (OPTIONAL) */}
        {activeTab === 'samples' && (
          <div className="samples-panel animate-fade-in">
            <div className="samples-header-note">
              <span className="note-badge">Benchmark Scenarios</span>
              <p>Select a bundled demonstration repository to observe pre-configured migration test cases.</p>
            </div>

            <div className="sample-apps-grid">
              {appsList.map((app) => {
                const isSelected = selectedSampleId === app.id;
                return (
                  <div 
                    key={app.id} 
                    className={`sample-app-card ${isSelected ? 'app-card-selected' : ''}`}
                    onClick={() => setSelectedSampleId(app.id)}
                  >
                    <div className="app-card-header">
                      <div className="app-type-tag">{app.type}</div>
                      <div className={`selection-radio ${isSelected ? 'radio-active' : ''}`}>
                        {isSelected && <div className="radio-inner-dot"></div>}
                      </div>
                    </div>

                    <h4 className="app-name">{app.name}</h4>
                    <p className="app-description">{app.description}</p>

                    <div className="app-meta-stats">
                      <span className="meta-stat-item">
                        <FileCode size={13} />
                        <span>{app.filesCount} files ({app.linesOfCode} LoC)</span>
                      </span>
                    </div>

                    <div className="app-tags-row">
                      {app.tags.map((tag) => (
                        <span key={tag} className="app-tag-pill">{tag}</span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Action & Launch Bar */}
        <div className="scan-launch-bar">
          <div className="pipeline-steps-preview">
            <span className="pipeline-step"><CheckCircle2 size={14} className="step-check" /> 1. AST Code Scan</span>
            <span className="pipeline-arrow">→</span>
            <span className="pipeline-step"><CheckCircle2 size={14} className="step-check" /> 2. PQC Benchmark</span>
            <span className="pipeline-arrow">→</span>
            <span className="pipeline-step"><CheckCircle2 size={14} className="step-check" /> 3. Tamper Verification</span>
            <span className="pipeline-arrow">→</span>
            <span className="pipeline-step"><CheckCircle2 size={14} className="step-check" /> 4. Decision Engine</span>
            <span className="pipeline-arrow">→</span>
            <span className="pipeline-step"><CheckCircle2 size={14} className="step-check" /> 5. Canonical Hash</span>
          </div>

          <div className="launch-btn-group">
            <button 
              className="btn-launch-scan"
              disabled={isScanning}
              onClick={handleLaunch}
            >
              {isScanning ? (
                <>
                  <div className="btn-spinner"></div>
                  <span>Scanning &amp; Calculating ({scanProgress}%)...</span>
                </>
              ) : (
                <>
                  <Play size={15} fill="#ffffff" />
                  <span>
                    {activeTab === 'paste' 
                      ? 'Calculate & Scan My Code' 
                      : activeTab === 'upload' 
                      ? 'Calculate & Scan Uploaded Archive' 
                      : 'Launch Sample Assessment'}
                  </span>
                  <ArrowRight size={15} />
                </>
              )}
            </button>
          </div>
        </div>

        {/* Scanning Progress Overlay */}
        {isScanning && (
          <div className="scan-progress-strip">
            <div className="progress-bar-track">
              <div 
                className="progress-bar-fill" 
                style={{ width: `${scanProgress}%` }}
              ></div>
            </div>
            <div className="progress-labels">
              <span>Evaluating cryptographic primitives &amp; Shor susceptibility...</span>
              <span><strong>{scanProgress}%</strong></span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

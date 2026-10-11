import React, { useState } from 'react';
import { 
  Bot, Network, CheckCircle, Terminal, Activity, ArrowRight, Server, ShieldCheck, Play, RefreshCw, X, Clock 
} from 'lucide-react';
import './AgentsView.css';

export default function AgentsView({ webSocketState }) {
  const [activeTab, setActiveTab] = useState('feed');
  const [selectedLog, setSelectedLog] = useState(null);

  const {
    isConnected,
    events,
    mcpLogs,
    activeAgentName,
    pipelineRunning,
    runSimulatedPipeline,
  } = webSocketState || {};

  const agents = [
    { name: 'Cryptographic Analysis Agent', shortName: 'Analysis', role: 'Semgrep & AST classical signature extraction' },
    { name: 'PQC Test Agent', shortName: 'PQC Test', role: 'liboqs harness (ML-DSA, SLH-DSA, Falcon)' },
    { name: 'Verification Agent', shortName: 'Verification', role: '4-scenario tamper verification tests' },
    { name: 'Decision Engine', shortName: 'Decision', role: 'System One latency triage & scoring' },
    { name: 'Report Agent', shortName: 'Report', role: 'Canonical JSON assembler & Anvil anchor' },
  ];

  return (
    <div className="agents-container animate-fade-in">
      {/* Top Orchestrator Pipeline Visualizer */}
      <div className="agent-pipeline-card">
        <div className="pipeline-header">
          <div className="pipeline-title-wrap">
            <Network size={18} className="pipeline-icon" />
            <h3 className="pipeline-title">Multi-Agent Orchestration Flow</h3>
          </div>

          <div className="pipeline-actions-top">
            <span className={`ws-status-badge ${isConnected ? 'ws-connected' : 'ws-fallback'}`}>
              <span className="ws-dot"></span>
              <span>{isConnected ? "Live WebSocket Connected (ws://localhost:8000)" : "Edge Fallback Simulation"}</span>
            </span>

            <button
              className="btn-trigger-pipeline"
              disabled={pipelineRunning}
              onClick={() => runSimulatedPipeline && runSimulatedPipeline()}
            >
              {pipelineRunning ? (
                <>
                  <div className="pipeline-spinner"></div>
                  <span>Streaming Pipeline...</span>
                </>
              ) : (
                <>
                  <Play size={13} fill="#ffffff" />
                  <span>Execute Pipeline Live</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Dynamic Nodes with Pulsing Active State */}
        <div className="agent-nodes-row">
          {agents.map((agent, idx) => {
            const isActive = activeAgentName === agent.name;
            return (
              <React.Fragment key={agent.name}>
                <div className={`agent-node-box ${isActive ? 'node-box-active-pulse' : ''}`}>
                  <div className={`node-icon-wrap ${isActive ? 'icon-wrap-pulse' : ''}`}>
                    <Bot size={18} />
                    <span className={`node-status-dot ${isActive ? 'dot-pulsing' : ''}`}></span>
                  </div>
                  <h4 className="node-agent-name">{agent.shortName}</h4>
                  <p className="node-role">{agent.role}</p>
                  <span className={`node-runs-tag ${isActive ? 'tag-running' : ''}`}>
                    {isActive ? "Executing..." : "Idle / Ready"}
                  </span>
                </div>
                {idx < agents.length - 1 && (
                  <div className="node-arrow-separator">
                    <ArrowRight size={16} />
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Tabs Row: Live Event Feed vs MCP Server Logs */}
      <div className="agent-events-section">
        <div className="events-header-bar">
          <div className="events-tab-buttons">
            <button
              className={`event-tab-btn ${activeTab === 'feed' ? 'active-event-tab' : ''}`}
              onClick={() => setActiveTab('feed')}
            >
              <Activity size={14} />
              <span>Live Agent Activity Stream ({events?.length ?? 0})</span>
            </button>
            <button
              className={`event-tab-btn ${activeTab === 'mcp' ? 'active-event-tab' : ''}`}
              onClick={() => setActiveTab('mcp')}
            >
              <Server size={14} />
              <span>MCP Server Call Logs ({mcpLogs?.length ?? 0})</span>
            </button>
          </div>

          <div className="mcp-allowed-badge">
            <ShieldCheck size={14} />
            <span>Path Allow-Listing: Active</span>
          </div>
        </div>

        {/* Tab 1: Live Activity Stream */}
        {activeTab === 'feed' && (
          <div className="events-stream-card">
            <div className="events-stream-list">
              {events?.map((evt) => (
                <div key={evt.id} className="stream-event-row animate-fade-in">
                  <span className="event-time">{evt.timestamp}</span>
                  <div className="event-agent-badge">
                    <Bot size={12} />
                    <span>{evt.agent}</span>
                  </div>
                  <span className={`event-type-pill pill-${evt.type}`}>
                    {evt.type.replace('_', ' ')}
                  </span>
                  <p className="event-msg">{evt.message}</p>
                  {evt.payload && (
                    <button 
                      className="btn-inspect-payload"
                      onClick={() => setSelectedLog(evt)}
                    >
                      Payload
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 2: MCP Server Call Log */}
        {activeTab === 'mcp' && (
          <div className="mcp-logs-card">
            <table className="mcp-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>MCP Server</th>
                  <th>Tool Called</th>
                  <th>Arguments</th>
                  <th>Duration</th>
                  <th>Allow-List</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {mcpLogs?.map((log) => (
                  <tr key={log.id} onClick={() => setSelectedLog(log)} className="mcp-row-clickable">
                    <td className="log-time">{log.timestamp}</td>
                    <td className="log-server">
                      <span className="server-name-tag">{log.server}</span>
                    </td>
                    <td className="log-tool">{log.tool}</td>
                    <td className="log-args">
                      <code>{JSON.stringify(log.arguments)}</code>
                    </td>
                    <td className="log-dur">{log.durationMs} ms</td>
                    <td className="log-allow">
                      <span className="allow-check">✓ Verified</span>
                    </td>
                    <td className="log-status">
                      <span className="status-success-badge">{log.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Tool / Payload Inspector Modal */}
      {selectedLog && (
        <div className="modal-backdrop animate-fade-in" onClick={() => setSelectedLog(null)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="modal-title">
                {selectedLog.tool ? `MCP Call: ${selectedLog.tool}` : `Agent Event Payload`}
              </h3>
              <button className="modal-close-btn" onClick={() => setSelectedLog(null)}>
                <X size={18} />
              </button>
            </div>
            <div className="modal-form">
              <pre className="inspector-json-pre">
                <code>{JSON.stringify(selectedLog, null, 2)}</code>
              </pre>
              <div className="modal-footer">
                <button className="btn-primary" onClick={() => setSelectedLog(null)}>
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

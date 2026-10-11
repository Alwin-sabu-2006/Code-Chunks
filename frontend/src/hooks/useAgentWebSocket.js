import { useState, useEffect, useRef, useCallback } from 'react';
import { MOCK_AGENT_EVENTS, MOCK_MCP_LOGS } from '../data/mockData';

export function useAgentWebSocket() {
  const [isConnected, setIsConnected] = useState(false);
  const [events, setEvents] = useState(MOCK_AGENT_EVENTS);
  const [mcpLogs, setMcpLogs] = useState(MOCK_MCP_LOGS);
  const [activeAgentName, setActiveAgentName] = useState(null);
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const socketRef = useRef(null);

  // Attempt real WebSocket connection to Member 3's backend
  useEffect(() => {
    let ws;
    try {
      ws = new WebSocket('ws://localhost:8000/ws');
      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onmessage = (msgEvent) => {
        try {
          const data = JSON.parse(msgEvent.data);
          if (data.type === 'agent_event') {
            const item = data.payload || data.data;
            setEvents((prev) => [item, ...prev]);
            setActiveAgentName(item.agent || item.agent_name);
          } else if (data.type === 'mcp_log' || data.type === 'mcp_call_log') {
            const item = data.payload || data.data;
            setMcpLogs((prev) => [item, ...prev]);
          }
        } catch (e) {
          console.warn('Failed parsing WS message:', e);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
      };

      ws.onerror = () => {
        setIsConnected(false);
      };

      socketRef.current = ws;
    } catch {
      setIsConnected(false);
    }

    return () => {
      if (ws) ws.close();
    };
  }, []);

  // Simulated live execution pipeline runner for Hackathon pitch / local standalone
  const runSimulatedPipeline = useCallback((onComplete) => {
    setPipelineRunning(true);
    setEvents([]);
    const sequence = [
      {
        delay: 300,
        event: {
          id: `evt-${Date.now()}-1`,
          timestamp: new Date().toLocaleTimeString(),
          agent: 'Cryptographic Analysis Agent',
          type: 'agent_started',
          message: 'Starting AST code scanner on contracts/ and src/ for classical crypto signatures.',
        },
      },
      {
        delay: 800,
        event: {
          id: `evt-${Date.now()}-2`,
          timestamp: new Date().toLocaleTimeString(),
          agent: 'Cryptographic Analysis Agent',
          type: 'tool_called',
          message: 'Invoked mcp-code-analysis:scan_solidity_signatures. Detected ecrecover in TokenWallet.sol:87.',
          payload: { flaw: 'ecrecover', file: 'TokenWallet.sol', line: 87 }
        },
      },
      {
        delay: 1300,
        event: {
          id: `evt-${Date.now()}-3`,
          timestamp: new Date().toLocaleTimeString(),
          agent: 'PQC Test Agent',
          type: 'agent_started',
          message: 'Executing liboqs comparative benchmark harness across ML-DSA, SLH-DSA and Falcon.',
        },
      },
      {
        delay: 1800,
        event: {
          id: `evt-${Date.now()}-4`,
          timestamp: new Date().toLocaleTimeString(),
          agent: 'PQC Test Agent',
          type: 'tool_called',
          message: 'Invoked mcp-benchmark:run_liboqs_bench (100 iterations completed, precision 1ns).',
        },
      },
      {
        delay: 2300,
        event: {
          id: `evt-${Date.now()}-5`,
          timestamp: new Date().toLocaleTimeString(),
          agent: 'Verification Agent',
          type: 'agent_started',
          message: 'Running 4-scenario tamper verification suite (Flipped bits & wrong public keys).',
        },
      },
      {
        delay: 2800,
        event: {
          id: `evt-${Date.now()}-6`,
          timestamp: new Date().toLocaleTimeString(),
          agent: 'Verification Agent',
          type: 'tool_called',
          message: 'Invoked mcp-crypto-test:tamper_matrix_verify. 100% tamper detection confirmed.',
        },
      },
      {
        delay: 3300,
        event: {
          id: `evt-${Date.now()}-7`,
          timestamp: new Date().toLocaleTimeString(),
          agent: 'Decision Engine',
          type: 'agent_started',
          message: 'System One rule classifier evaluating risk coefficients (latency: 18.4ms).',
        },
      },
      {
        delay: 3800,
        event: {
          id: `evt-${Date.now()}-8`,
          timestamp: new Date().toLocaleTimeString(),
          agent: 'Report Agent',
          type: 'agent_finished',
          message: 'Canonical JSON assembled. SHA-256 anchored on Anvil blockchain block #42.',
        },
      },
    ];

    sequence.forEach(({ delay, event }, index) => {
      setTimeout(() => {
        setEvents((prev) => [event, ...prev]);
        setActiveAgentName(event.agent);

        if (index === sequence.length - 1) {
          setPipelineRunning(false);
          setActiveAgentName(null);
          if (onComplete) onComplete();
        }
      }, delay);
    });
  }, []);

  return {
    isConnected,
    events,
    mcpLogs,
    activeAgentName,
    pipelineRunning,
    runSimulatedPipeline,
  };
}

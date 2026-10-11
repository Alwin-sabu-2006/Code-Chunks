import React, { useState } from 'react';
import { 
  Mic, Volume2, Clock, Send, Sparkles, ChevronDown, ChevronUp, Radio, CheckCircle2, Shield 
} from 'lucide-react';
import './VoiceInterfaceHUD.css';

export default function VoiceInterfaceHUD({ voiceState, isOpen, onClose, onToggleExpand }) {
  const [typedInput, setTypedInput] = useState('');
  const [isExpanded, setIsExpanded] = useState(false);

  const {
    isListening,
    transcript,
    lastCommand,
    voiceLatencyMs,
    isSpeaking,
    feedbackMessage,
    commandHistory,
    audioLevel,
    startListening,
    stopListening,
    executeTypedCommand,
  } = voiceState || {};

  const handleSendTyped = (e) => {
    e.preventDefault();
    if (!typedInput.trim()) return;
    executeTypedCommand(typedInput);
    setTypedInput('');
  };

  const sampleIntents = [
    "Scan the sample wallet",
    "Compare ML-DSA with ECDSA",
    "What is the highest risk finding?",
    "Anchor this report",
    "Show agent activity",
    "Verify report",
    "Toggle airplane mode",
    "Reset demo",
  ];

  return (
    <div className={`voice-hud-dock ${isExpanded ? 'voice-hud-expanded' : ''} animate-fade-in`}>
      {/* Top Header Bar */}
      <div className="voice-hud-bar" onClick={() => setIsExpanded(!isExpanded)}>
        <div className="hud-bar-left">
          <div className={`hud-mic-pill ${isListening ? 'pill-listening' : isSpeaking ? 'pill-speaking' : ''}`}>
            {isSpeaking ? <Volume2 size={15} /> : <Mic size={15} />}
            <span>{isListening ? "Listening..." : isSpeaking ? "Speaking..." : "Voice Assistant"}</span>
          </div>

          {/* Animated Waveform Visualizer */}
          <div className="hud-wave-visualizer">
            {[40, 75, 30, 90, 60, 80, 45, 95, 50, 70].map((h, i) => {
              const activeHeight = (isListening || isSpeaking) ? Math.max(15, (h * audioLevel) / 100) : 4;
              return (
                <span 
                  key={i} 
                  className="wave-bar" 
                  style={{ height: `${activeHeight}px` }}
                ></span>
              );
            })}
          </div>
        </div>

        <div className="hud-bar-right">
          <div className="hud-latency-pill">
            <Clock size={12} />
            <span>Speech-to-Reply: <strong>{voiceLatencyMs}ms</strong></span>
            <span className="latency-target-check">(&lt;1000ms PASS)</span>
          </div>

          <button className="expand-dock-btn" title="Toggle full voice console">
            {isExpanded ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
          </button>
        </div>
      </div>

      {/* Expanded Console View */}
      {isExpanded && (
        <div className="voice-expanded-body animate-fade-in">
          {/* Status Message / Response */}
          <div className="voice-response-card">
            <div className="response-header">
              <Sparkles size={14} className="response-icon" />
              <span className="response-title">Latest Spoken Response</span>
            </div>
            <p className="response-text">{feedbackMessage}</p>
          </div>

          {/* 8-Command Quick Chip Carousel */}
          <div className="quick-intents-wrap">
            <span className="intents-header-label">8 Standardized Voice Intents:</span>
            <div className="intents-chips-scroll">
              {sampleIntents.map((intent) => (
                <button
                  key={intent}
                  className="intent-chip-btn"
                  onClick={() => executeTypedCommand(intent)}
                >
                  "{intent}"
                </button>
              ))}
            </div>
          </div>

          {/* Typed Fallback Input (Section 7.7: Always keep typed fallback for noisy rooms) */}
          <form onSubmit={handleSendTyped} className="typed-command-form">
            <input 
              type="text"
              placeholder="Type command fallback (e.g. 'Compare ML-DSA with ECDSA')..."
              value={typedInput}
              onChange={(e) => setTypedInput(e.target.value)}
              className="typed-input"
            />
            <button type="submit" className="typed-send-btn">
              <Send size={14} />
              <span>Send</span>
            </button>
          </form>

          {/* Push-to-Talk Big Button */}
          <div className="push-to-talk-bar">
            <button
              className={`big-ptt-btn ${isListening ? 'ptt-listening' : ''}`}
              onMouseDown={startListening}
              onMouseUp={stopListening}
              onTouchStart={startListening}
              onTouchEnd={stopListening}
            >
              <Mic size={18} />
              <span>{isListening ? "Release to Send" : "Hold to Talk (Push-to-Talk)"}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

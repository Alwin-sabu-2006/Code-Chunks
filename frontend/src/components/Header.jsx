import React, { useState, useEffect } from 'react';
import { 
  Search, Mail, Bell, Mic, MicOff, Volume2, ShieldCheck, Cpu, Clock, Zap, HelpCircle, ArrowDownToLine 
} from 'lucide-react';
import './Header.css';

export default function Header({ 
  searchQuery, 
  setSearchQuery, 
  voiceState, 
  isAirplaneMode, 
  onToggleAirplaneMode,
}) {
  const [showNotificationMenu, setShowNotificationMenu] = useState(false);
  const [showVoiceModal, setShowVoiceModal] = useState(false);

  const {
    isListening,
    transcript,
    lastCommand,
    voiceLatencyMs,
    isSpeaking,
    feedbackMessage,
    startListening,
    stopListening,
    executeTypedCommand,
  } = voiceState || {};

  // Keyboard shortcut listener for Cmd+F / Ctrl+F
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault();
        const searchInput = document.getElementById('header-search-input');
        if (searchInput) searchInput.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <header className="header-container">
      {/* Left: Search Bar */}
      <div className="header-search-wrapper">
        <Search size={17} className="search-icon" />
        <input
          id="header-search-input"
          type="text"
          placeholder="Search finding, algorithm, MCP..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="search-input"
        />
        <div className="shortcut-badge">
          <span>⌘</span>
          <span>F</span>
        </div>
      </div>

      {/* Middle: Edge Privacy & Latency HUD (Requirements 4.6 & 4.7) */}
      <div className="header-latency-hud">
        {/* Edge Models Badge */}
        <button 
          className={`hud-edge-badge ${isAirplaneMode ? 'badge-airplane-active' : ''}`}
          onClick={onToggleAirplaneMode}
          title="Toggle Airplane Mode (Local Models Only)"
        >
          <span className="edge-pulse-dot"></span>
          <span>{isAirplaneMode ? "✈ Airplane Mode (Offline)" : "Runs Locally"}</span>
        </button>

        {/* Voice Latency Badge */}
        <div className="hud-metric-pill" title="Target < 1000ms: Speech End to TTS Audio Start">
          <Clock size={12} className="hud-metric-icon" />
          <span>Voice: <strong>{voiceLatencyMs}ms</strong></span>
        </div>

        {/* Decision Engine Latency Badge */}
        <div className="hud-metric-pill" title="Target < 50ms: System One Triage Classifier">
          <Zap size={12} className="hud-metric-icon text-amber" />
          <span>Decision: <strong>18.4ms</strong></span>
        </div>

        {/* 1-Click Downloadable PDF Dossier */}
        <a 
          href="/Q_Chain_Member_5_Delivery_Dossier.pdf"
          download="Q_Chain_Member_5_Delivery_Dossier.pdf"
          className="header-download-btn"
          title="Download Member 5 Official PDF Dossier (4 Pages)"
        >
          <ArrowDownToLine size={13} />
          <span>Download PDF</span>
        </a>
      </div>

      {/* Right Actions: Mic Push-to-Talk, Notifications, Profile */}
      <div className="header-actions">
        {/* Voice Push-to-Talk Button */}
        <div className="relative-wrap">
          <button 
            className={`action-icon-btn mic-action-btn ${isListening ? 'mic-active-pulse' : ''} ${isSpeaking ? 'tts-speaking-pulse' : ''}`}
            onMouseDown={startListening}
            onMouseUp={stopListening}
            onTouchStart={startListening}
            onTouchEnd={stopListening}
            onClick={() => setShowVoiceModal(!showVoiceModal)}
            title="Push to Talk (Hold or Click for Voice Assistant)"
          >
            {isListening ? (
              <Mic size={18} className="mic-on-icon" />
            ) : isSpeaking ? (
              <Volume2 size={18} className="tts-on-icon" />
            ) : (
              <Mic size={18} />
            )}
          </button>
        </div>

        {/* Notifications */}
        <div className="relative-wrap">
          <button 
            className="action-icon-btn" 
            title="Notifications"
            onClick={() => setShowNotificationMenu(!showNotificationMenu)}
          >
            <Bell size={18} />
            <span className="dot-indicator green-dot"></span>
          </button>
        </div>
      </div>
    </header>
  );
}

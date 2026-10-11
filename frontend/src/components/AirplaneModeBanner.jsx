import React from 'react';
import { Plane, Cpu, ShieldCheck, X } from 'lucide-react';
import './AirplaneModeBanner.css';

export default function AirplaneModeBanner({ isAirplaneMode, onToggle }) {
  if (!isAirplaneMode) return null;

  return (
    <div className="airplane-banner-bar animate-fade-in">
      <div className="airplane-banner-left">
        <div className="plane-icon-circle">
          <Plane size={15} />
        </div>
        <div className="plane-text-col">
          <span className="plane-headline">AIRPLANE MODE ACTIVE • ZERO CLOUD DATA EGRESS</span>
          <span className="plane-subtext">
            Operating exclusively via local edge models (Ollama, local Whisper STT, Piper TTS, in-process liboqs). No source code or hashes sent to external networks.
          </span>
        </div>
      </div>

      <div className="airplane-banner-right">
        <span className="audit-badge">
          <ShieldCheck size={13} />
          <span>Offline Audit Verified</span>
        </span>
        <button 
          className="exit-airplane-btn"
          onClick={onToggle}
          title="Disable Airplane Mode"
        >
          <span>Exit Airplane Mode</span>
          <X size={13} />
        </button>
      </div>
    </div>
  );
}

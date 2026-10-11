import React from 'react';
import { 
  LayoutGrid, 
  Search, 
  ShieldAlert, 
  BarChart2, 
  Network, 
  FileCheck2, 
  ShieldCheck, 
  Sliders, 
  HelpCircle, 
  FileText,
  ArrowDownToLine,
  ExternalLink
} from 'lucide-react';
import './Sidebar.css';

export default function Sidebar({ activeNav = 'Dashboard', setActiveNav }) {
  const menuItems = [
    { id: 'Dashboard', label: 'Dashboard', icon: LayoutGrid },
    { id: 'New Scan', label: 'New Scan', icon: Search },
    { id: 'Findings', label: 'Findings', icon: ShieldAlert, badge: '5' },
    { id: 'Benchmarks', label: 'Benchmarks', icon: BarChart2 },
    { id: 'Agents', label: 'Agent Activity', icon: Network },
    { id: 'Report', label: 'Report & Anchor', icon: FileCheck2 },
    { id: 'Verify', label: 'Verification', icon: ShieldCheck },
  ];

  const generalItems = [
    { id: 'Dossier', label: 'Delivery Dossier', icon: FileText, href: '/Q_Chain_Member_5_Delivery_Dossier.html', isExternal: true },
    { id: 'Settings', label: 'Settings', icon: Sliders },
    { id: 'Help', label: 'Documentation', icon: HelpCircle },
  ];

  return (
    <aside className="sidebar-container">
      {/* Brand Logo */}
      <div className="sidebar-brand">
        <div className="brand-logo-icon">
          <svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="14" cy="14" r="12" stroke="#10b981" strokeWidth="2.5" />
            <circle cx="14" cy="14" r="5" fill="#10b981" />
            <path d="M14 4C19.5228 4 24 8.47715 24 14" stroke="#38bdf8" strokeWidth="2.5" strokeLinecap="round" />
          </svg>
        </div>
        <div className="brand-text-col">
          <span className="brand-title">Q-Chain</span>
          <span className="brand-sub-badge">PQC Migration</span>
        </div>
      </div>

      {/* Main Navigation */}
      <div className="sidebar-content">
        <div className="sidebar-section">
          <span className="section-label">ASSESSMENT WORKSPACE</span>
          <nav className="nav-list">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeNav === item.id;
              return (
                <button
                  key={item.id}
                  className={`nav-item ${isActive ? 'nav-item-active' : ''}`}
                  onClick={() => setActiveNav(item.id)}
                >
                  <div className="nav-item-left">
                    <Icon size={17} className="nav-icon" />
                    <span className="nav-label">{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className={`nav-badge ${isActive ? 'badge-on-active' : ''}`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* General Navigation */}
        <div className="sidebar-section">
          <span className="section-label">PLATFORM &amp; DOCS</span>
          <nav className="nav-list">
            {generalItems.map((item) => {
              const Icon = item.icon;
              if (item.isExternal) {
                return (
                  <a
                    key={item.id}
                    href={item.href}
                    target="_blank"
                    rel="noreferrer"
                    className="nav-item nav-item-external"
                    style={{ textDecoration: 'none' }}
                  >
                    <div className="nav-item-left">
                      <Icon size={17} className="nav-icon" style={{ color: '#38bdf8' }} />
                      <span className="nav-label" style={{ color: '#38bdf8' }}>{item.label}</span>
                    </div>
                    <ExternalLink size={12} style={{ opacity: 0.6 }} />
                  </a>
                );
              }
              const isActive = activeNav === item.id;
              return (
                <button
                  key={item.id}
                  className={`nav-item ${isActive ? 'nav-item-active' : ''}`}
                  onClick={() => setActiveNav(item.id)}
                >
                  <div className="nav-item-left">
                    <Icon size={17} className="nav-icon" />
                    <span className="nav-label">{item.label}</span>
                  </div>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Promo Card for Dossier */}
        <div className="sidebar-promo-card">
          <div className="promo-bg-texture"></div>
          <div className="promo-icon-wrap">
            <FileText size={16} className="promo-phone-icon" />
          </div>
          <h4 className="promo-title">Official Delivery Dossier</h4>
          <p className="promo-subtitle">Full Phase 0-5 documentation, metrics scorecard &amp; pitch guide.</p>
          <a 
            href="/Q_Chain_Member_5_Delivery_Dossier.html" 
            target="_blank" 
            rel="noreferrer" 
            className="promo-btn"
            style={{ textDecoration: 'none' }}
          >
            <span>Open Portal</span>
            <ExternalLink size={12} />
          </a>
        </div>
      </div>
    </aside>
  );
}

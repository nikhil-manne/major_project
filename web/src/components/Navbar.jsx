import React from 'react';

const ROLE_TABS = {
  admin: [
    { id: 'labs', label: 'Common Labs', icon: '●', color: '#38bdf8', activeClass: 'active-blue' },
    { id: 'red', label: 'Red Team', icon: '●', color: '#ef4444', activeClass: 'active-red' },
    { id: 'blue', label: 'Blue Team', icon: '●', color: '#06b6d4', activeClass: 'active-blue' },
    { id: 'mitre', label: 'MITRE Matrix', icon: '●', color: '#3b82f6', activeClass: 'active-blue' },
    { id: 'soc', label: 'SOC Desk', icon: '●', color: '#10b981', activeClass: 'active-soc' },
    { id: 'replay', label: 'Replay Studio', icon: '●', color: '#8b5cf6', activeClass: 'active-admin' },
    { id: 'ci', label: 'CI/CD Gate', icon: '●', color: '#f59e0b', activeClass: 'active-blue' },
    { id: 'admin', label: 'Admin', icon: '●', color: '#a855f7', activeClass: 'active-admin' },
    { id: 'users', label: 'Users', icon: '●', color: '#a855f7', activeClass: 'active-admin' },
  ],
  red: [
    { id: 'red', label: 'Red Team Console', icon: '●', color: '#ef4444', activeClass: 'active-red' },
    { id: 'labs', label: 'Common Labs', icon: '●', color: '#38bdf8', activeClass: 'active-blue' },
    { id: 'mitre', label: 'MITRE Matrix', icon: '●', color: '#3b82f6', activeClass: 'active-blue' },
  ],
  blue: [
    { id: 'blue', label: 'Blue Team Hub', icon: '●', color: '#06b6d4', activeClass: 'active-blue' },
    { id: 'labs', label: 'Common Labs', icon: '●', color: '#38bdf8', activeClass: 'active-blue' },
    { id: 'mitre', label: 'MITRE Matrix', icon: '●', color: '#3b82f6', activeClass: 'active-blue' },
  ],
  soc: [
    { id: 'soc', label: 'SOC Analyst Desk', icon: '●', color: '#10b981', activeClass: 'active-soc' },
    { id: 'labs', label: 'Common Labs', icon: '●', color: '#38bdf8', activeClass: 'active-blue' },
    { id: 'replay', label: 'Replay Studio', icon: '●', color: '#8b5cf6', activeClass: 'active-admin' },
  ],
};

export default function Navbar({
  currentRole,
  setCurrentRole,
  activeMode,
  onSeedDemo,
  seeding,
  user,
  onLogout,
  activeSessionId,
}) {
  const allowedTabs = ROLE_TABS[user?.role] || ROLE_TABS.red;

  return (
    <header className="navbar" id="main-navbar">
      <div className="brand-section">
        <div className="brand-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <div>
          <div className="brand-title">CYBER RANGE</div>
          <div className="brand-subtitle">Security Validation Platform</div>
        </div>
      </div>

      <nav className="nav-tabs" aria-label="Role Navigation">
        {allowedTabs.map(tab => (
          <button
            key={tab.id}
            id={`nav-tab-${tab.id}`}
            className={`nav-tab-btn ${currentRole === tab.id ? tab.activeClass : ''}`}
            onClick={() => setCurrentRole(tab.id)}
          >
            <span className="tab-dot" style={{ background: tab.color }} />
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="nav-right">
        <button
          className={`sandbox-chip ${activeSessionId ? 'is-active' : ''}`}
          onClick={() => setCurrentRole('labs')}
          title={activeSessionId ? 'Click to manage or switch sandboxes in Common Labs' : 'No sandbox active. Click to select or launch a sandbox'}
        >
          <span className="pulse" />
          {activeSessionId ? <span>Sandbox: <strong>{activeSessionId}</strong></span> : <span>No active sandbox</span>}
        </button>

        {user?.role === 'admin' && (
          <button
            id="btn-seed-demo"
            className="btn btn-primary"
            style={{ padding: '6px 12px', fontSize: '0.8rem' }}
            onClick={onSeedDemo}
            disabled={seeding}
            title="Run complete end-to-end cyber simulation loop"
          >
            {seeding ? 'Running simulation…' : 'Run demo loop'}
          </button>
        )}

        <div
          className={`role-chip role-${user?.role || 'admin'}`}
          title={`Signed in as ${user?.username} (${user?.role_label || user?.role})`}
        >
          <div className="role-chip-avatar">{(user?.username || '?').slice(0, 1).toUpperCase()}</div>
          <div className="role-chip-text">
            <strong>{user?.username}</strong>
            <span>{user?.role_label || user?.role}</span>
          </div>
        </div>

        <button id="btn-logout" className="btn btn-outline nav-logout" onClick={onLogout} title="Sign out">
          Sign out
        </button>
      </div>
    </header>
  );
}

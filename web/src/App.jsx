import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import LabsOverview from './components/LabsOverview';
import RedTeamConsole from './components/RedTeamConsole';
import BlueTeamHub from './components/BlueTeamHub';
import MitreNavigatorMatrix from './components/MitreNavigatorMatrix';
import SocAnalystDesk from './components/SocAnalystDesk';
import ReplayStudio from './components/ReplayStudio';
import CiGateView from './components/CiGateView';
import AdminOverview from './components/AdminOverview';
import CopilotDrawer from './components/CopilotDrawer';
import LoginPage from './components/LoginPage';
import UserManagement from './components/UserManagement';

// Strict Role-Based Access Control Mapping
const ROLE_PERMITTED_SECTIONS = {
  admin: ['admin', 'users', 'labs', 'red', 'blue', 'mitre', 'soc', 'replay', 'ci'],
  red: ['red', 'labs', 'mitre'],
  blue: ['blue', 'labs', 'mitre'],
  soc: ['soc', 'labs', 'replay'],
};

const ROLE_DEFAULT_SECTION = {
  admin: 'admin',
  red: 'red',
  blue: 'blue',
  soc: 'soc',
};

// Attach a bearer token to same-origin API calls before React components mount.
if (typeof window !== 'undefined' && !window.__cyberRangeFetchWrapped) {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = function(input, options = {}) {
    const requestUrl = typeof input === 'string' ? input : input?.url || String(input);
    const isApiRequest = requestUrl.startsWith('/api/') || requestUrl.startsWith(`${window.location.origin}/api/`);
    const token = sessionStorage.getItem('cyberrange_access_token') || '';
    if (!isApiRequest || !token) return nativeFetch(input, options);
    const baseHeaders = options.headers || (input instanceof Request ? input.headers : undefined);
    const headers = new Headers(baseHeaders || {});
    if (!headers.has('Authorization')) headers.set('Authorization', `Bearer ${token}`);
    return nativeFetch(input, { ...options, headers }).then(response => {
      if (response.status === 401 && !requestUrl.includes('/api/v1/auth/login')) {
        sessionStorage.removeItem('cyberrange_access_token');
        window.dispatchEvent(new CustomEvent('cyberrange:unauthorized'));
      }
      return response;
    });
  };
  window.__cyberRangeFetchWrapped = true;
}

export default function App() {
  const [currentRole, setCurrentRole] = useState('labs');
  const [user, setUser] = useState(null);
  const [authReady, setAuthReady] = useState(false);
  const [activeMode, setActiveMode] = useState('unknown');
  const [events, setEvents] = useState([]);
  const [activeSessionId, setActiveSessionId] = useState(null);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [copilotInitialPrompt, setCopilotInitialPrompt] = useState('');
  const [seeding, setSeeding] = useState(false);
  const [toastMessage, setToastMessage] = useState('');

  // Restore a session if one exists.
  useEffect(() => {
    let cancelled = false;
    const savedToken = sessionStorage.getItem('cyberrange_access_token') || '';
    if (!savedToken) {
      setAuthReady(true);
      return () => { cancelled = true; };
    }
    fetch('/api/v1/auth/me', { headers: { Authorization: `Bearer ${savedToken}` } })
      .then(res => { if (!res.ok) throw new Error('Session expired'); return res.json(); })
      .then(data => {
        if (!cancelled) {
          setUser(data);
          const allowed = ROLE_PERMITTED_SECTIONS[data.role] || ['labs'];
          setCurrentRole(prev => (allowed.includes(prev) ? prev : (ROLE_DEFAULT_SECTION[data.role] || 'labs')));
        }
      })
      .catch(() => {
        sessionStorage.removeItem('cyberrange_access_token');
        if (!cancelled) setUser(null);
      })
      .finally(() => { if (!cancelled) setAuthReady(true); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    const onUnauthorized = () => {
      setUser(null);
      setEvents([]);
      setActiveSessionId(null);
      setIsCopilotOpen(false);
      setCurrentRole('labs');
    };
    window.addEventListener('cyberrange:unauthorized', onUnauthorized);
    return () => window.removeEventListener('cyberrange:unauthorized', onUnauthorized);
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/v1/system/health')
      .then(res => { if (!res.ok) throw new Error(`Health API returned HTTP ${res.status}`); return res.json(); })
      .then(data => { if (!cancelled) setActiveMode(data.execution_mode || 'unknown'); })
      .catch(() => { if (!cancelled) setActiveMode('unavailable'); });
    return () => { cancelled = true; };
  }, []);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(''), 4500);
  };

  const fetchEvents = () => {
    fetch('/api/v1/events?limit=200')
      .then(res => { if (!res.ok) throw new Error(`Events API returned HTTP ${res.status}`); return res.json(); })
      .then(data => {
        setEvents(Array.isArray(data) ? data : []);
        if (!activeSessionId) {
          const withSession = data.find(e => e.session_id);
          if (withSession) setActiveSessionId(withSession.session_id);
        }
      })
      .catch(() => {});
  };

  // Poll active sessions so activeSessionId is pre-populated if sessions exist
  useEffect(() => {
    if (!user) return;
    fetch('/api/v1/sessions')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data) && data.length > 0 && !activeSessionId) {
          const activeOne = data.find(s => s.status === 'active') || data[0];
          if (activeOne) setActiveSessionId(activeOne.session_id);
        }
      })
      .catch(() => {});
  }, [user]);

  useEffect(() => {
    if (!user) return undefined;
    fetchEvents();
    const interval = setInterval(fetchEvents, 3000);
    return () => clearInterval(interval);
  }, [user, activeSessionId]);

  const handleLogin = (payload) => {
    sessionStorage.setItem('cyberrange_access_token', payload.access_token);
    setUser(payload.user);
    const role = payload.user?.role;
    setCurrentRole(ROLE_DEFAULT_SECTION[role] || 'labs');
    setAuthReady(true);
  };

  const handleLogout = () => {
    sessionStorage.removeItem('cyberrange_access_token');
    setUser(null);
    setEvents([]);
    setActiveSessionId(null);
    setIsCopilotOpen(false);
    setCurrentRole('labs');
  };

  const handleSeedDemo = async () => {
    if (user?.role !== 'admin') {
      showToast("Access denied: only administrators can run the demo seed simulation.");
      return;
    }
    setSeeding(true);
    showToast("Running full end-to-end cyber range simulation...");
    try {
      const res = await fetch('/api/v1/system/demo-seed', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail?.message || data.detail || `HTTP ${res.status}`);
      setActiveSessionId(data.session_id);
      fetchEvents();
      showToast(`Demo simulation complete: session ${data.session_id} created with ${data.scenarios_submitted} attack scenarios!`);
    } catch (err) {
      showToast("Demo seeding failed: " + err.message);
    } finally {
      setSeeding(false);
    }
  };

  const handleSelectTechniqueForCopilot = (technique) => {
    setCopilotInitialPrompt(`Technique ${technique.technique_id} (${technique.name}) has status ${technique.status} in session ${activeSessionId || 'not selected'}. Review the stored evidence and explain whether a verified live detection gap exists before suggesting a draft Sigma rule.`);
    setIsCopilotOpen(true);
  };

  if (!authReady) {
    return <div className="auth-loading"><div className="auth-loading-mark">CR</div><p>Restoring session…</p></div>;
  }
  if (!user) return <LoginPage onLogin={handleLogin} />;

  // Verify whether the currently chosen section is permitted for the user's role
  const allowedSections = ROLE_PERMITTED_SECTIONS[user?.role] || ['labs'];
  const isSectionAllowed = allowedSections.includes(currentRole);

  return (
    <div className="app-container">
      {/* Top Navbar with Role-Gated Navigation */}
      <Navbar
        currentRole={currentRole}
        setCurrentRole={setCurrentRole}
        activeMode={activeMode}
        onSeedDemo={handleSeedDemo}
        seeding={seeding}
        user={user}
        onLogout={handleLogout}
        activeSessionId={activeSessionId}
      />

      {/* Main View Container */}
      <main className="main-content">
        {/* Toast Alert */}
        {toastMessage && <div className="toast" role="status">{toastMessage}</div>}

        {/* Access Restriction Guard for Direct Nav Attempts */}
        {!isSectionAllowed ? (
          <div className="glass-panel access-denied">
            <div className="access-denied-icon" aria-hidden="true">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
            </div>
            <h2>Access restricted</h2>
            <p>
              Your account role is <strong style={{ color: 'var(--text-main)' }}>{user.role_label || user.role}</strong>. You can only open your team's workspace and the common labs, so <strong style={{ color: 'var(--text-main)' }}>{currentRole}</strong> isn't available to you.
            </p>
            <button
              className="btn btn-primary"
              onClick={() => setCurrentRole(ROLE_DEFAULT_SECTION[user.role] || 'labs')}
            >
              Return to {user.role_label || 'your workspace'}
            </button>
          </div>
        ) : (
          <>
            {/* Dynamic Role / Module Routing */}
            {currentRole === 'labs' && (
              <LabsOverview
                user={user}
                activeSessionId={activeSessionId}
                onSelectSession={setActiveSessionId}
                onNavigateRole={setCurrentRole}
              />
            )}

            {currentRole === 'red' && (
              <RedTeamConsole
                activeSessionId={activeSessionId}
                events={events}
                onRefreshEvents={fetchEvents}
                onNavigateRole={setCurrentRole}
              />
            )}

            {currentRole === 'blue' && (
              <BlueTeamHub
                activeSessionId={activeSessionId}
                events={events}
                onRefreshEvents={fetchEvents}
                onNavigateRole={setCurrentRole}
              />
            )}

            {currentRole === 'mitre' && (
              <MitreNavigatorMatrix
                activeSessionId={activeSessionId}
                onSelectTechniqueForCopilot={handleSelectTechniqueForCopilot}
              />
            )}

            {currentRole === 'soc' && (
              <SocAnalystDesk
                activeSessionId={activeSessionId}
                onNavigateRole={setCurrentRole}
              />
            )}

            {currentRole === 'replay' && (
              <ReplayStudio
                activeSessionId={activeSessionId}
                onRefreshEvents={fetchEvents}
              />
            )}

            {currentRole === 'ci' && user.role === 'admin' && (
              <CiGateView
                onRefreshEvents={fetchEvents}
              />
            )}

            {currentRole === 'admin' && user.role === 'admin' && (
              <AdminOverview
                onRefreshEvents={fetchEvents}
              />
            )}

            {currentRole === 'users' && user.role === 'admin' && (
              <UserManagement currentUser={user} />
            )}
          </>
        )}
      </main>

      {/* Floating AI Security Copilot Action Button */}
      {!isCopilotOpen && (
        <button
          id="btn-open-copilot"
          className="copilot-fab"
          onClick={() => setIsCopilotOpen(true)}
          title="Open AI Security Copilot"
        >
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" /></svg>
        </button>
      )}

      {/* AI Security Copilot Drawer */}
      <CopilotDrawer
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
        currentRole={currentRole}
        activeSessionId={activeSessionId}
        initialPrompt={copilotInitialPrompt}
      />
    </div>
  );
}

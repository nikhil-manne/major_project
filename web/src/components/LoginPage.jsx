import React, { useState } from 'react';

export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(event) {
    event.preventDefault();
    setError('');
    setBusy(true);
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail || `Login failed (HTTP ${response.status})`);
      onLogin(payload);
    } catch (err) {
      setError(err.message || 'Unable to sign in. Check that the backend is running.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-shell">
      <section className="login-card">
        <div className="login-brand-mark" aria-hidden="true">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
        </div>
        <div className="login-eyebrow">Secure access</div>
        <h1>Cyber Range</h1>
        <p className="login-subtitle">Security Validation Platform</p>
        <div className="login-divider" />
        <form onSubmit={submit} className="login-form">
          <label htmlFor="login-username">Username</label>
          <input id="login-username" name="username" autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} required autoFocus placeholder="Enter your username" />
          <label htmlFor="login-password">Password</label>
          <input id="login-password" name="password" type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} required placeholder="Enter your password" />
          {error && <div className="login-error" role="alert">{error}</div>}
          <button className="login-submit" type="submit" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
            {!busy && <span aria-hidden="true">→</span>}
          </button>
        </form>
        <p className="login-footer"><span className="login-status-dot" /> Protected by role-based access control</p>
      </section>
      <p className="login-bottom-note">Authorized users only · Access is audited by role</p>
    </div>
  );
}

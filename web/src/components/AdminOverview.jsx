import React, { useState, useEffect } from 'react';

export default function AdminOverview({ onRefreshEvents }) {
  const [sessions, setSessions] = useState([]);
  const [systemHealth, setSystemHealth] = useState(null);
  const [dockerfileText, setDockerfileText] = useState(`FROM node:latest\nUSER root\nRUN apt-get update && apt-get install -y curl\nRUN curl -sSL http://example.com/install.sh | bash\nENV ADMIN_PASSWORD=supersecret123\nCMD ["npm", "start"]`);
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const fetchSessionsAndHealth = () => {
    fetch('/api/v1/sessions')
      .then(res => res.json())
      .then(data => setSessions(data))
      .catch(() => {});

    fetch('/api/v1/system/health')
      .then(res => res.json())
      .then(data => setSystemHealth(data))
      .catch(() => {});
  };

  useEffect(() => {
    fetchSessionsAndHealth();
  }, []);

  const handleDestroySession = async (sessionId) => {
    try {
      await fetch(`/api/v1/sessions/${sessionId}`, { method: 'DELETE' });
      fetchSessionsAndHealth();
      onRefreshEvents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleScanDockerfile = async () => {
    setScanning(true);
    try {
      const res = await fetch('/api/v1/sessions/scan-dockerfile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dockerfile: dockerfileText })
      });
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      console.error(err);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
      {/* Left Column: Sandbox Sessions & System Health */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {/* System Health Card */}
        {systemHealth && (
          <div className="glass-panel" style={{ padding: '20px' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px', color: '#c084fc' }}>
              Backend Liveness
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <div style={{ background: 'rgba(255,255,255,0.02)', padding: '10px 14px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>API status</div>
                <div style={{ fontSize: '0.88rem', fontWeight: 700, color: systemHealth.status === 'ok' ? '#34d399' : '#f87171' }}>{systemHealth.status || 'unknown'}</div>
              </div>
              <div style={{ background: 'rgba(255,255,255,0.02)', padding: '10px 14px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Configured execution mode</div>
                <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#38bdf8' }}>{systemHealth.execution_mode || 'unknown'}</div>
              </div>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '10px' }}>
              This endpoint confirms API liveness only. It does not verify PostgreSQL, Kafka, OpenSearch, MinIO, Keycloak, or Kubernetes health.
            </p>
          </div>
        )}

        {/* Active Sandbox Sessions */}
        <div className="glass-panel" style={{ padding: '20px', flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <h3 style={{ fontSize: '1.05rem' }}>Active & Ephemeral Sandboxes</h3>
            <span className="badge badge-untested">{sessions.length} Sessions</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '420px', overflowY: 'auto' }}>
            {sessions.length === 0 ? (
              <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-dim)' }}>
                No active sandboxes. Create one from Red Team or trigger a CI gate.
              </div>
            ) : (
              sessions.map(s => (
                <div
                  key={s.session_id}
                  style={{
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '12px 16px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{s.session_id}</span>
                      <span className={`badge ${s.status === 'active' ? 'badge-covered' : 'badge-untested'}`}>
                        {s.status}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      Namespace: <code>{s.namespace}</code> | Target: {s.target_image}
                    </div>
                  </div>

                  {s.status === 'active' && (
                    <button
                      className="btn btn-danger"
                      style={{ padding: '5px 10px', fontSize: '0.75rem' }}
                      onClick={() => handleDestroySession(s.session_id)}
                    >
                      Destroy Sandbox
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Right Column: Pre-Deployment Security Scanner (Hadolint / Trivy) */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', color: '#f59e0b' }}>
          Dockerfile Static Policy Checker
        </h3>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
          Runs static Dockerfile policy heuristics (and Hadolint only if configured). This endpoint does not build an image or run Trivy against an image; review the reported mode and findings.
        </p>

        <textarea
          id="textarea-dockerfile-scan"
          value={dockerfileText}
          onChange={(e) => setDockerfileText(e.target.value)}
          style={{
            width: '100%',
            minHeight: '180px',
            background: '#05070c',
            border: '1px solid #1e293b',
            borderRadius: 'var(--radius-md)',
            color: '#e2e8f0',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.82rem',
            padding: '12px',
            outline: 'none',
            resize: 'vertical',
            marginBottom: '12px'
          }}
        />

        <button
          id="btn-scan-dockerfile"
          className="btn btn-primary"
          onClick={handleScanDockerfile}
          disabled={scanning}
          style={{ marginBottom: '16px' }}
        >
          {scanning ? "Scanning..." : "Run Static Dockerfile Checks"}
        </button>

        {scanResult && (
          <div style={{
            background: scanResult.passed ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
            border: `1px solid ${scanResult.passed ? '#10b981' : '#ef4444'}`,
            borderRadius: 'var(--radius-md)',
            padding: '16px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <strong style={{ color: scanResult.passed ? '#34d399' : '#f87171' }}>
                {scanResult.verified
                  ? (scanResult.passed ? "✔ TOOL-BASED CHECKS PASSED" : "✖ TOOL-BASED CHECKS FAILED")
                  : (scanResult.passed ? "⚠ HEURISTIC CHECKS PASSED (UNVERIFIED)" : "✖ HEURISTIC CHECKS FAILED (UNVERIFIED)")}
              </strong>
              <span className="badge badge-untested">
                {scanResult.engine || 'static checker'} · {scanResult.mode || 'unknown'} · {scanResult.verified ? 'verified tool output' : 'unverified heuristic'}
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '180px', overflowY: 'auto' }}>
              {scanResult.findings.map((f, i) => (
                <div key={i} style={{ fontSize: '0.78rem', color: '#fca5a5' }}>
                  <strong>[Line {f.line}] {f.rule} ({f.severity}):</strong> {f.message}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

import React, { useState, useEffect } from 'react';

export default function CiGateView({ onRefreshEvents }) {
  const [builds, setBuilds] = useState([]);
  const [triggering, setTriggering] = useState(false);
  const [selectedBuild, setSelectedBuild] = useState(null);
  const [repoInput, setRepoInput] = useState('acme/core-banking-api');
  const [imageInput, setImageInput] = useState('vulnerable-struts-app:2.3.31');

  const fetchBuilds = () => {
    fetch('/api/v1/ci-gate/builds')
      .then(res => res.json())
      .then(data => {
        setBuilds(data);
        if (data.length > 0 && !selectedBuild) {
          setSelectedBuild(data[0]);
        }
      })
      .catch(() => {});
  };

  useEffect(() => {
    fetchBuilds();
  }, []);

  const handleTriggerCiBuild = async () => {
    setTriggering(true);
    try {
      const res = await fetch('/api/v1/ci-gate/webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository: repoInput,
          image_tag: imageInput,
          branch: 'main',
          min_score_threshold: 75.0
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail?.message || data.detail || `HTTP ${res.status}`);
      fetchBuilds();
      setSelectedBuild(data);
      onRefreshEvents();
    } catch (err) {
      setSelectedBuild({ gate_result: 'ERROR', report_markdown: err.message, readiness_score: null, coverage_percentage: 0, gap_count: 0 });
    } finally {
      setTriggering(false);
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '24px' }}>
      {/* Left Column: CI/CD Pipeline Simulator & Runs List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {/* Trigger Card */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px', color: '#f59e0b' }}>
            Trigger CI/CD Security Gate Run
          </h3>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
            Simulates a pull-request or build webhook triggering automated ephemeral sandbox deployment, scripted attack execution, and automated pass/fail release gating.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div>
              <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', fontWeight: 600 }}>Repository</label>
              <input
                id="input-ci-repo"
                type="text"
                value={repoInput}
                onChange={(e) => setRepoInput(e.target.value)}
                style={{
                  width: '100%',
                  background: '#090d16',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '8px 12px',
                  color: '#ffffff',
                  fontSize: '0.85rem',
                  fontFamily: 'var(--font-mono)'
                }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.78rem', color: 'var(--text-dim)', fontWeight: 600 }}>Target Build Image</label>
              <input
                id="input-ci-image"
                type="text"
                value={imageInput}
                onChange={(e) => setImageInput(e.target.value)}
                style={{
                  width: '100%',
                  background: '#090d16',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '8px 12px',
                  color: '#ffffff',
                  fontSize: '0.85rem',
                  fontFamily: 'var(--font-mono)'
                }}
              />
            </div>

            <button
              id="btn-trigger-ci"
              className="btn btn-primary"
              onClick={handleTriggerCiBuild}
              disabled={triggering}
              style={{ marginTop: '8px' }}
            >
              {triggering ? "Running Automated Security Gate..." : "Trigger GitHub Actions Gate"}
            </button>
          </div>
        </div>

        {/* Historical Pipeline Runs */}
        <div className="glass-panel" style={{ padding: '20px', flex: 1 }}>
          <h3 style={{ fontSize: '1rem', marginBottom: '14px' }}>Tested Pipeline Builds</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '420px', overflowY: 'auto' }}>
            {builds.length === 0 ? (
              <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-dim)' }}>
                No automated builds tested yet. Click "Trigger GitHub Actions Gate" above.
              </div>
            ) : (
              builds.map(b => (
                <div
                  key={b.build_id}
                  onClick={() => setSelectedBuild(b)}
                  style={{
                    background: selectedBuild?.build_id === b.build_id ? 'rgba(56, 189, 248, 0.1)' : 'rgba(255,255,255,0.02)',
                    border: `1px solid ${selectedBuild?.build_id === b.build_id ? '#38bdf8' : 'var(--border-subtle)'}`,
                    borderRadius: 'var(--radius-sm)',
                    padding: '12px 14px',
                    cursor: 'pointer'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.88rem' }}>
                      commit: {b.commit_hash}
                    </span>
                    <span className={`badge ${b.gate_result === 'PASS' ? 'badge-covered' : 'badge-gap'}`}>
                      {b.gate_result}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {b.repository} ({b.branch}) | Score: <strong>{b.readiness_score}/100</strong>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Right Column: Build Security Gate Report Inspector */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        {selectedBuild ? (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <span className={`badge ${selectedBuild.gate_result === 'PASS' ? 'badge-covered' : 'badge-gap'}`} style={{ marginBottom: '6px' }}>
                  GATE RESULT: {selectedBuild.gate_result}
                </span>
                <h2 style={{ fontSize: '1.4rem' }}>Build Security Report</h2>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>Readiness Score</div>
                <div style={{ fontSize: '2rem', fontWeight: 900, color: selectedBuild.readiness_score >= 75 ? '#34d399' : '#f87171' }}>
                  {selectedBuild.readiness_score} <span style={{ fontSize: '1rem', color: 'var(--text-dim)' }}>/ 100</span>
                </div>
              </div>
            </div>

            <div style={{
              background: '#090d16',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              padding: '16px',
              marginBottom: '16px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.84rem',
              lineHeight: 1.6
            }}>
              <div><strong>Build ID:</strong> {selectedBuild.build_id}</div>
              <div><strong>Commit:</strong> {selectedBuild.commit_hash}</div>
              <div><strong>Repository:</strong> {selectedBuild.repository}</div>
              <div><strong>Image Tag:</strong> {selectedBuild.image_tag}</div>
              <div><strong>MITRE Coverage:</strong> {selectedBuild.coverage_percentage}%</div>
              <div><strong>Undetected Gaps:</strong> {selectedBuild.gap_count}</div>
              <div><strong>Ephemeral Sandbox:</strong> {selectedBuild.session_id} (destroyed & archived)</div>
            </div>

            <h4 style={{ fontSize: '0.9rem', marginBottom: '8px', color: '#38bdf8' }}>CI Markdown Artifact Summary</h4>
            <pre style={{
              background: '#05070c',
              border: '1px solid #1e293b',
              borderRadius: 'var(--radius-sm)',
              padding: '14px',
              fontSize: '0.8rem',
              color: '#94a3b8',
              whiteSpace: 'pre-wrap',
              maxHeight: '260px',
              overflowY: 'auto'
            }}>
              {selectedBuild.report_markdown}
            </pre>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-dim)' }}>
            Select a build run to inspect the detailed security gate audit report.
          </div>
        )}
      </div>
    </div>
  );
}

import React, { useState, useEffect } from 'react';

export default function MitreNavigatorMatrix({ activeSessionId, onSelectTechniqueForCopilot }) {
  const [coverageData, setCoverageData] = useState(null);
  const [tactics, setTactics] = useState([]);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sessionScope, setSessionScope] = useState('active');

  const getEffectiveSessionId = () => {
    if (sessionScope === 'all') return '';
    return activeSessionId || null;
  };

  const fetchCoverage = () => {
    setLoading(true);
    const sid = getEffectiveSessionId();
    const tacticsRequest = fetch('/api/v1/validation/tactics').then(r => {
      if (!r.ok) throw new Error('Unable to load tactics');
      return r.json();
    });
    if (sid === null) {
      // Do not accidentally turn an empty active-session selection into an all-session query.
      setCoverageData(null);
      tacticsRequest.then(setTactics).catch(() => setTactics([])).finally(() => setLoading(false));
      return;
    }
    Promise.all([
      fetch(`/api/v1/validation/coverage?session_id=${encodeURIComponent(sid)}`).then(r => {
        if (!r.ok) throw new Error('Unable to load coverage');
        return r.json();
      }),
      tacticsRequest
    ])
      .then(([cov, tacs]) => {
        setCoverageData(cov);
        setTactics(tacs);
      })
      .catch(() => setCoverageData(null))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchCoverage();
  }, [activeSessionId, sessionScope]);

  const handleExportLayer = () => {
    const sid = getEffectiveSessionId();
    if (sid === null) return;
    window.open(`/api/v1/validation/navigator-layer?session_id=${encodeURIComponent(sid)}`, '_blank');
  };

  const getStatusColor = (status) => {
    if (status === 'covered') return '#10b981';   // green — live attack + linked detection
    if (status === 'gap') return '#ef4444';        // red — live attack, no detection
    if (status === 'simulated') return '#f59e0b';  // amber — simulated only, not confirmed on real target
    return '#64748b';                               // slate — untested
  };

  const getStatusBg = (status) => {
    if (status === 'covered') return 'rgba(16, 185, 129, 0.15)';
    if (status === 'gap') return 'rgba(239, 68, 68, 0.15)';
    if (status === 'simulated') return 'rgba(245, 158, 11, 0.12)';
    return 'rgba(100, 116, 139, 0.1)';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Banner: Metrics & Differentiator Callout */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <h2 style={{ fontSize: '1.4rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
              MITRE ATT&CK Matrix & Security Validation
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '4px' }}>
              <strong>Outcome-Based Coverage:</strong> Counts only explicitly linked live attack-to-detection evidence. Simulated attacks are shown separately and do not count as verified coverage; this limited matrix is not full ATT&CK coverage.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: '#090d16', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', padding: '5px 10px' }}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Scope:</span>
              <select
                id="select-mitre-scope"
                value={sessionScope}
                onChange={(e) => setSessionScope(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#38bdf8',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  outline: 'none',
                  cursor: 'pointer'
                }}
              >
                <option value="active" style={{ background: '#0f172a', color: '#f1f5f9' }}>Active Session ({activeSessionId || 'none selected'})</option>
                <option value="all" style={{ background: '#0f172a', color: '#f1f5f9' }}>All Sessions (Aggregate)</option>
              </select>
            </div>

            <button
              id="btn-export-navigator"
              className="btn btn-outline"
              onClick={handleExportLayer}
              style={{ fontSize: '0.82rem' }}
            >
              Export Navigator v4.5 Layer
            </button>
            <button
              id="btn-refresh-coverage"
              className="btn btn-primary"
              onClick={fetchCoverage}
              style={{ fontSize: '0.82rem' }}
            >
              Refresh Heatmap
            </button>
          </div>
        </div>

        {/* Coverage Counters */}
        {coverageData && (
          <div className="stat-grid" style={{ marginTop: '20px', marginBottom: 0 }}>
            <div className="glass-panel stat-card blue">
              <div className="stat-title">Validation Coverage</div>
              <div className="stat-value" style={{ color: '#38bdf8' }}>
                {coverageData.coverage_percentage}%
              </div>
            </div>
            <div className="glass-panel stat-card green">
              <div className="stat-title">Proven Covered</div>
              <div className="stat-value" style={{ color: '#34d399' }}>
                {coverageData.covered_count}
              </div>
            </div>
            <div className="glass-panel stat-card red">
              <div className="stat-title">Detection Gaps</div>
              <div className="stat-value" style={{ color: '#f87171' }}>
                {coverageData.gap_count}
              </div>
            </div>
            <div className="glass-panel stat-card purple">
              <div className="stat-title">Untested Techniques</div>
              <div className="stat-value" style={{ color: '#94a3b8' }}>
                {coverageData.untested_count}
              </div>
            </div>
            {(coverageData.simulated_count > 0) && (
              <div className="glass-panel stat-card" style={{ borderColor: 'rgba(245,158,11,0.3)' }}>
                <div className="stat-title">Simulated Only</div>
                <div className="stat-value" style={{ color: '#f59e0b' }}
                  title="Exercises ran in simulation mode — not confirmed against a real target. Excluded from verified coverage.">
                  {coverageData.simulated_count}
                </div>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '4px' }}>not confirmed on target</div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Do not display aggregate coverage under an empty active-session selection. */}
      {sessionScope === 'active' && !activeSessionId ? (
        <div className="glass-panel" style={{ padding: '24px', color: 'var(--text-muted)' }}>
          <h3 style={{ color: '#e2e8f0', marginBottom: '8px' }}>Select a session to view its coverage</h3>
          <p>Launch or select a session, or switch the scope to “All Sessions (Aggregate)” to view aggregate results.</p>
        </div>
      ) : (
      /* Interactive Matrix Grid (Tactics Columns) */
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '14px',
        overflowX: 'auto',
        paddingBottom: '16px'
      }}>
        {tactics.map(tac => {
          const matchingTechniques = coverageData?.techniques.filter(t => t.tactic_id === tac.id) || [];
          return (
            <div
              key={tac.id}
              className="glass-panel"
              style={{
                padding: '14px',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
                minWidth: '200px'
              }}
            >
              <div style={{
                borderBottom: '1px solid var(--border-subtle)',
                paddingBottom: '8px',
                fontSize: '0.85rem',
                fontWeight: 700,
                color: '#e2e8f0',
                display: 'flex',
                justifyContent: 'space-between'
              }}>
                <span>{tac.name}</span>
                <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>{tac.id}</span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {matchingTechniques.length === 0 ? (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', padding: '10px 0' }}>No techniques loaded</div>
                ) : (
                  matchingTechniques.map(tech => (
                    <div
                      key={tech.technique_id}
                      onClick={() => setSelectedTechnique(tech)}
                      style={{
                        padding: '10px 12px',
                        borderRadius: 'var(--radius-sm)',
                        background: getStatusBg(tech.status),
                        border: `1px solid ${getStatusColor(tech.status)}`,
                        cursor: 'pointer',
                        transition: 'transform 0.15s ease'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-2px)'}
                      onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.82rem', color: '#ffffff' }}>
                          {tech.technique_id}
                        </span>
                        <span className={`badge badge-${tech.status}`} style={{ fontSize: '0.68rem', padding: '1px 6px' }}>
                          {tech.status.toUpperCase()}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.3 }}>
                        {tech.name}
                      </div>
                      {tech.latency_sec !== null && (
                        <div style={{ fontSize: '0.7rem', color: '#38bdf8', marginTop: '4px' }}>
                          Caught in {tech.latency_sec}s
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>
      )}

      {/* Technique Detail Modal */}
      {selectedTechnique && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1100,
          padding: '20px'
        }}>
          <div className="glass-panel" style={{ maxWidth: '640px', width: '100%', padding: '24px', background: '#0d121f' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <span className="badge" style={{
                  background: getStatusBg(selectedTechnique.status),
                  color: getStatusColor(selectedTechnique.status),
                  borderColor: getStatusColor(selectedTechnique.status),
                  marginBottom: '6px'
                }}>
                  {selectedTechnique.status.toUpperCase()}
                </span>
                <h3 style={{ fontSize: '1.25rem', color: '#f8fafc' }}>
                  {selectedTechnique.technique_id}: {selectedTechnique.name}
                </h3>
              </div>
              <button
                className="btn btn-outline"
                style={{ padding: '4px 10px', fontSize: '0.8rem' }}
                onClick={() => setSelectedTechnique(null)}
              >
                ✕ Close
              </button>
            </div>

            <p style={{ fontSize: '0.86rem', color: 'var(--text-muted)', marginBottom: '16px', lineHeight: 1.5 }}>
              {selectedTechnique.description}
            </p>

            <div style={{
              background: '#07090e',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              padding: '14px',
              fontSize: '0.82rem',
              marginBottom: '16px'
            }}>
              <div style={{ marginBottom: '6px' }}>
                <strong>Tactic:</strong> {selectedTechnique.tactic_name} ({selectedTechnique.tactic_id})
              </div>
              <div style={{ marginBottom: '6px' }}>
                <strong>Attacks Executed:</strong> {selectedTechnique.attacks_count}
              </div>
              <div style={{ marginBottom: '6px' }}>
                <strong>Detections Fired:</strong> {selectedTechnique.detections_count}
              </div>
              {selectedTechnique.latency_sec !== null && (
                <div>
                  <strong>Detection Latency:</strong> {selectedTechnique.latency_sec} seconds
                </div>
              )}
            </div>

            {selectedTechnique.evidence && selectedTechnique.evidence.length > 0 && (
              <div style={{ marginBottom: '16px' }}>
                <h4 style={{ fontSize: '0.9rem', marginBottom: '8px', color: '#38bdf8' }}>Validation Evidence</h4>
                <div style={{ maxHeight: '140px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {selectedTechnique.evidence.map((ev, i) => (
                    <div key={i} style={{ background: 'rgba(255,255,255,0.03)', padding: '8px 12px', borderRadius: '4px', fontSize: '0.78rem' }}>
                      Rule Match: <code>{ev.rule}</code> (Lag: {ev.latency_sec}s)
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              {selectedTechnique.status === 'gap' && (
                <button
                  className="btn btn-primary"
                  style={{ fontSize: '0.82rem' }}
                  onClick={() => {
                    onSelectTechniqueForCopilot(selectedTechnique);
                    setSelectedTechnique(null);
                  }}
                >
                  Ask AI Copilot to Draft Sigma Rule
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

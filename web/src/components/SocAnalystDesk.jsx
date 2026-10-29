import React, { useState, useEffect } from 'react';

export default function SocAnalystDesk({ activeSessionId, onNavigateRole }) {
  const [readiness, setReadiness] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [huntQuery, setHuntQuery] = useState('');
  const [huntResults, setHuntResults] = useState(null);
  const [hunting, setHunting] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);

  const fetchScoreAndIncidents = () => {
    fetch(`/api/v1/scoring/score?session_id=${activeSessionId || ''}`)
      .then(res => res.json())
      .then(data => setReadiness(data))
      .catch(() => {});

    fetch('/api/v1/scoring/incidents')
      .then(res => res.json())
      .then(data => setIncidents(data))
      .catch(() => {});
  };

  useEffect(() => {
    fetchScoreAndIncidents();
  }, [activeSessionId]);

  const handleUpdateIncidentStatus = async (incId, newStatus) => {
    try {
      await fetch(`/api/v1/scoring/incidents/${incId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus, analyst_notes: `Status changed to ${newStatus} by soc1` })
      });
      fetchScoreAndIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  const handleRunHunt = async (e) => {
    e.preventDefault();
    if (!huntQuery.trim()) return;
    setHunting(true);
    try {
      const res = await fetch('/api/v1/scoring/hunt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query_text: huntQuery, session_id: activeSessionId })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail?.message || data.detail || `HTTP ${res.status}`);
      setHuntResults(data);
    } catch (err) {
      console.error(err);
    } finally {
      setHunting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Section: Security Readiness Scorecard */}
      {readiness && (
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
            <div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                Enterprise Readiness Benchmark
              </div>
              <h2 style={{ fontSize: '1.6rem', marginTop: '4px' }}>
                Security Readiness Scorecard
              </h2>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '6px' }}>
                {activeSessionId ? (
                  <span className="badge badge-soc" style={{ fontSize: '0.78rem' }}>Target Sandbox: {activeSessionId}</span>
                ) : (
                  <button
                    className="badge badge-soc"
                    style={{ cursor: 'pointer', border: '1px solid #10b981' }}
                    onClick={() => onNavigateRole && onNavigateRole('labs')}
                    title="Click to launch or select an active sandbox in Common Labs"
                  >
                    No Sandbox Active · Go to Common Labs ➜
                  </button>
                )}
                {activeSessionId && onNavigateRole && (
                  <button
                    className="btn btn-secondary"
                    style={{ padding: '2px 8px', fontSize: '0.72rem' }}
                    onClick={() => onNavigateRole('labs')}
                    title="Switch target sandbox in Common Labs"
                  >
                    Switch
                  </button>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{
                background: readiness.score >= 75 ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                border: `2px solid ${readiness.score >= 75 ? '#10b981' : '#ef4444'}`,
                padding: '8px 24px',
                borderRadius: 'var(--radius-lg)',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Grade</div>
                <div style={{ fontSize: '2rem', fontWeight: 900, color: readiness.score >= 75 ? '#34d399' : '#f87171' }}>
                  {readiness.breakdown?.grade || 'B'}
                </div>
              </div>

              <div>
                <div style={{ fontSize: '2.4rem', fontWeight: 900, fontFamily: 'var(--font-heading)' }}>
                  {readiness.score} <span style={{ fontSize: '1.2rem', color: 'var(--text-dim)' }}>/ 100</span>
                </div>
                <span className={`badge ${readiness.breakdown?.ready_for_production ? 'badge-covered' : 'badge-gap'}`}>
                  {readiness.breakdown?.production_readiness_verified ? "✔ Verified" : "⚠ Production readiness not verified"}
                </span>
              </div>
            </div>
          </div>

          <div className="stat-grid" style={{ marginTop: '20px', marginBottom: 0 }}>
            <div className="glass-panel stat-card blue">
              <div className="stat-title">Attack Techniques Covered</div>
              <div className="stat-value" style={{ color: '#38bdf8' }}>
                {readiness.coverage_pct}%
              </div>
            </div>
            <div className="glass-panel stat-card green">
              <div className="stat-title">Avg Detection Latency</div>
              <div className="stat-value" style={{ color: '#34d399' }}>
                {readiness.avg_detection_latency_sec}s
              </div>
            </div>
            <div className="glass-panel stat-card red">
              <div className="stat-title">Unresolved Incidents</div>
              <div className="stat-value" style={{ color: readiness.unresolved_incidents > 0 ? '#f87171' : '#34d399' }}>
                {readiness.unresolved_incidents}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Middle Section: Threat Hunting Query Bar */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <h3 style={{ fontSize: '1.05rem', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          Normalized Event Hunting
        </h3>
        <form onSubmit={handleRunHunt} style={{ display: 'flex', gap: '12px' }}>
          <input
            id="input-threat-hunt"
            type="text"
            placeholder="Search currently ingested tenant events (OpenSearch only when configured; e.g. 'ms17_010', 'portscan', '445')..."
            value={huntQuery}
            onChange={(e) => setHuntQuery(e.target.value)}
            style={{
              flex: 1,
              background: '#090d16',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              padding: '10px 16px',
              color: '#ffffff',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.88rem',
              outline: 'none'
            }}
          />
          <button
            id="btn-run-hunt"
            type="submit"
            className="btn btn-primary"
            disabled={hunting}
          >
            {hunting ? "Searching..." : "Hunt"}
          </button>
        </form>

        {huntResults && (
          <div style={{ marginTop: '16px' }}>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
              Found {huntResults.matches_count} matching event(s) for query <code>"{huntResults.query}"</code>:
            </div>
            <div style={{ maxHeight: '200px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {huntResults.results.map((r, i) => (
                <div key={i} style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)', padding: '8px 12px', borderRadius: '4px', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
                  [{r.source_type}] {r.action} (Technique: {r.mitre_technique || 'None'})
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Bottom Section: SOC Incident Triage & Case Management */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            SOC Incident Triage Queue
          </h3>
          <span className="badge badge-critical">{incidents.length} Active Cases</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {incidents.length === 0 ? (
            <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)' }}>
              No critical incidents open. Run attacks or simulation to populate triage queue.
            </div>
          ) : (
            incidents.map((inc) => (
              <div
                key={inc.incident_id}
                style={{
                  background: 'rgba(15, 23, 42, 0.9)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  padding: '16px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                    <span style={{ fontWeight: 800, color: '#f8fafc', fontSize: '0.92rem' }}>
                      {inc.incident_id}
                    </span>
                    <span className={`badge ${inc.severity === 'critical' ? 'badge-critical' : 'badge-gap'}`}>
                      {inc.severity.toUpperCase()}
                    </span>
                    <span className="badge badge-untested" style={{ textTransform: 'capitalize' }}>
                      Status: {inc.status}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.9rem', color: '#e2e8f0', marginBottom: '4px' }}>
                    {inc.title}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    MITRE Technique: <strong style={{ color: '#38bdf8' }}>{inc.mitre_technique || 'T1210'}</strong> |
                    Assigned: <span style={{ color: '#94a3b8' }}>{inc.assigned_to}</span> |
                    Time: {new Date(inc.created_at).toLocaleTimeString()}
                  </div>
                </div>

                {/* Status Transition Action Buttons */}
                <div style={{ display: 'flex', gap: '8px' }}>
                  {inc.status === 'open' && (
                    <button
                      className="btn btn-outline"
                      style={{ fontSize: '0.78rem', padding: '6px 12px' }}
                      onClick={() => handleUpdateIncidentStatus(inc.incident_id, 'investigating')}
                    >
                      Investigate
                    </button>
                  )}
                  {inc.status === 'investigating' && (
                    <button
                      className="btn btn-outline"
                      style={{ fontSize: '0.78rem', padding: '6px 12px', borderColor: '#10b981', color: '#34d399' }}
                      onClick={() => handleUpdateIncidentStatus(inc.incident_id, 'contained')}
                    >
                      Contain
                    </button>
                  )}
                  {(inc.status === 'contained' || inc.status === 'investigating') && (
                    <button
                      className="btn btn-primary"
                      style={{ fontSize: '0.78rem', padding: '6px 12px' }}
                      onClick={() => handleUpdateIncidentStatus(inc.incident_id, 'resolved')}
                    >
                      Resolve Case
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

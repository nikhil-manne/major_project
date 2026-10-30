import React, { useState, useEffect } from 'react';

export default function SocAnalystDesk({ activeSessionId, onNavigateRole }) {
  const [readiness, setReadiness] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [huntQuery, setHuntQuery] = useState('');
  const [huntResults, setHuntResults] = useState(null);
  const [hunting, setHunting] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [labReport, setLabReport] = useState(null);
  const [labReportLoading, setLabReportLoading] = useState(false);
  const [labReportError, setLabReportError] = useState(null);

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

  const fetchLabReport = async (labId) => {
    if (!labId) return;
    setLabReportLoading(true);
    setLabReportError(null);
    try {
      const res = await fetch(`/api/v1/scoring/lab-report/${encodeURIComponent(labId)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setLabReport(data);
    } catch (err) {
      setLabReportError(err.message);
    } finally {
      setLabReportLoading(false);
    }
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

      {/* Lab Assessment Report */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '1.05rem' }}>
            Lab Assessment Report
          </h3>
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            {labReport && (
              <span className="badge badge-soc" style={{ fontSize: '0.75rem' }}>Lab: {labReport.lab_id}</span>
            )}
            <button
              id="btn-fetch-lab-report"
              className="btn btn-outline"
              style={{ fontSize: '0.8rem', padding: '5px 12px' }}
              onClick={() => {
                // Try to derive lab_id from the active session info, or prompt user
                const labId = labReport?.lab_id || window.prompt('Enter lab ID (e.g. lab-abc123):');
                if (labId) fetchLabReport(labId);
              }}
              disabled={labReportLoading}
            >
              {labReportLoading ? 'Loading...' : labReport ? 'Refresh Report' : 'Load Lab Report'}
            </button>
          </div>
        </div>

        {labReportError && (
          <div style={{ color: '#f87171', fontSize: '0.82rem', marginBottom: '12px' }}>
            Error: {labReportError}
          </div>
        )}

        {!labReport && !labReportLoading && (
          <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
            Click 'Load Lab Report' to fetch the full per-lab assessment: static findings, CVEs, red/blue team event summary, and recommendations.
          </div>
        )}

        {labReport && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {/* Summary strip */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '10px' }}>
              {[
                { label: 'Static Findings', value: labReport.summary?.static_findings_count ?? 0, color: '#f59e0b' },
                { label: 'CVEs', value: labReport.summary?.cve_count ?? 0, color: '#ef4444' },
                { label: 'Critical CVEs', value: labReport.summary?.critical_cve_count ?? 0, color: '#dc2626' },
                { label: 'Attack Events', value: labReport.summary?.attack_events ?? 0, color: '#f87171' },
                { label: 'Detection Events', value: labReport.summary?.detection_events ?? 0, color: '#34d399' },
                { label: 'Readiness Score', value: labReport.summary?.readiness_score ?? 'N/A', color: '#38bdf8' },
              ].map(({ label, value, color }) => (
                <div key={label} style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', padding: '10px 14px' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>{label}</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 700, color }}>{value}</div>
                </div>
              ))}
            </div>

            {/* Provenance disclosure */}
            {labReport.provenance_disclosure && (
              <div style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)', borderRadius: 'var(--radius-sm)', padding: '10px 14px', fontSize: '0.8rem', color: '#fbbf24' }}>
                <strong>Provenance:</strong> {labReport.provenance_disclosure}
              </div>
            )}

            {/* Static policy findings */}
            {labReport.static_findings?.length > 0 && (
              <div>
                <h4 style={{ fontSize: '0.9rem', color: '#f59e0b', marginBottom: '8px' }}>Static Policy Findings ({labReport.static_findings.length})</h4>
                <div style={{ maxHeight: '150px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {labReport.static_findings.map((f, i) => (
                    <div key={i} style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', background: 'rgba(255,255,255,0.02)', padding: '6px 10px', borderRadius: '4px' }}>
                      <span style={{ color: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? '#f87171' : '#fbbf24' }}>[{f.severity}]</span>{' '}
                      {f.rule}: {f.message}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* CVE list */}
            {labReport.cves?.length > 0 && (
              <div>
                <h4 style={{ fontSize: '0.9rem', color: '#ef4444', marginBottom: '8px' }}>Image CVEs ({labReport.cves.length})</h4>
                <div style={{ maxHeight: '150px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {labReport.cves.map((c, i) => (
                    <div key={i} style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', background: 'rgba(239,68,68,0.04)', padding: '6px 10px', borderRadius: '4px', display: 'flex', gap: '12px' }}>
                      <span style={{ color: c.severity === 'CRITICAL' ? '#dc2626' : c.severity === 'HIGH' ? '#f87171' : '#fbbf24', fontWeight: 700 }}>{c.severity}</span>
                      <span style={{ color: '#38bdf8' }}>{c.cve_id}</span>
                      <span style={{ color: 'var(--text-muted)' }}>{c.package} {c.version}</span>
                      {c.fixed_version && <span style={{ color: '#34d399' }}>→ {c.fixed_version}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            {labReport.recommendations?.length > 0 && (
              <div>
                <h4 style={{ fontSize: '0.9rem', color: '#38bdf8', marginBottom: '8px' }}>Recommendations</h4>
                <ul style={{ paddingLeft: '18px', margin: 0, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {labReport.recommendations.map((r, i) => (
                    <li key={i} style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

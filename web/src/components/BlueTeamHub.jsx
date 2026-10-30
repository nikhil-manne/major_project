import React, { useState, useEffect } from 'react';

export default function BlueTeamHub({ activeSessionId, events, onRefreshEvents, onNavigateRole }) {
  const [activeTab, setActiveTab] = useState('alerts'); // 'alerts' | 'vulnerabilities' | 'health'
  const [rules, setRules] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [sensorHealth, setSensorHealth] = useState(null);
  const [selectedRule, setSelectedRule] = useState(null);
  const [editorYaml, setEditorYaml] = useState('');
  const [evaluating, setEvaluating] = useState(false);
  const [validationResult, setValidationResult] = useState(null);

  const fetchRules = () => {
    fetch('/api/v1/detection/rules')
      .then(res => res.json())
      .then(data => {
        setRules(data);
        if (data.length > 0 && !selectedRule) {
          setSelectedRule(data[0]);
          setEditorYaml(data[0].sigma_yaml);
        }
      })
      .catch(() => {});
  };

  const fetchAlerts = () => {
    if (!activeSessionId) {
      setAlerts([]);
      return;
    }
    fetch(`/api/v1/detection/alerts?session_id=${encodeURIComponent(activeSessionId)}`)
      .then(res => res.json())
      .then(data => setAlerts(data))
      .catch(() => {});
  };

  const fetchVulnerabilities = () => {
    fetch('/api/v1/detection/vulnerabilities')
      .then(res => res.json())
      .then(data => setVulnerabilities(Array.isArray(data) ? data : []))
      .catch(() => {});
  };

  const fetchSensorHealth = () => {
    fetch('/api/v1/detection/sensor-health')
      .then(res => res.json())
      .then(data => setSensorHealth(data))
      .catch(() => {});
  };

  useEffect(() => {
    fetchRules();
    fetchAlerts();
    fetchVulnerabilities();
    fetchSensorHealth();
  }, [activeSessionId]);

  const handleSelectRule = (rule) => {
    setSelectedRule(rule);
    setEditorYaml(rule.sigma_yaml);
    setValidationResult(null);
  };

  const handleValidateRule = async () => {
    try {
      const res = await fetch('/api/v1/detection/rules/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sigma_yaml: editorYaml })
      });
      const data = await res.json();
      setValidationResult(data);
    } catch (err) {
      setValidationResult({ valid: false, error: err.message });
    }
  };

  const handleSaveRule = async () => {
    try {
      const res = await fetch('/api/v1/detection/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sigma_yaml: editorYaml })
      });
      if (res.ok) {
        fetchRules();
        setValidationResult({ valid: true, message: "Rule compiled and deployed successfully!" });
      } else {
        const err = await res.json();
        setValidationResult({ valid: false, error: err.detail });
      }
    } catch (err) {
      setValidationResult({ valid: false, error: err.message });
    }
  };

  const handleEvaluateDetections = async () => {
    if (!activeSessionId) {
      setValidationResult({ valid: false, error: 'Select or launch a session in Labs before evaluating detections.' });
      return;
    }
    setEvaluating(true);
    try {
      const res = await fetch('/api/v1/detection/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: activeSessionId })
      });
      if (!res.ok) throw new Error(`Detection evaluation returned HTTP ${res.status}`);
      fetchAlerts();
      onRefreshEvents();
    } catch (err) {
      console.error(err);
    } finally {
      setEvaluating(false);
    }
  };

  const rawDetections = activeSessionId
    ? ((alerts && alerts.length > 0)
        ? alerts
        : events.filter(e => e.source_type === 'detection' && e.session_id === activeSessionId))
    : [];

  // Deduplicate alerts by triggering_event_id so no attack is displayed twice
  const seenTriggers = new Set();
  const detectionEvents = rawDetections.filter(al => {
    const triggerId = al.raw_payload?.triggering_event_id;
    if (triggerId) {
      if (seenTriggers.has(triggerId)) return false;
      seenTriggers.add(triggerId);
    }
    return true;
  });

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '24px' }}>
      {/* Left Column: Tabs for Alerts, Vulnerability Queue, and Sensor Health */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
        {/* Tab Headers */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px', flexWrap: 'wrap', gap: '10px' }}>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className="btn"
              style={{
                background: activeTab === 'alerts' ? 'rgba(6, 182, 212, 0.2)' : 'transparent',
                borderColor: activeTab === 'alerts' ? '#06b6d4' : 'transparent',
                color: activeTab === 'alerts' ? '#38bdf8' : 'var(--text-muted)',
                fontSize: '0.84rem',
                padding: '6px 12px'
              }}
              onClick={() => setActiveTab('alerts')}
            >
              Detection Alerts ({detectionEvents.length})
            </button>
            <button
              className="btn"
              style={{
                background: activeTab === 'vulnerabilities' ? 'rgba(168, 85, 247, 0.2)' : 'transparent',
                borderColor: activeTab === 'vulnerabilities' ? '#a855f7' : 'transparent',
                color: activeTab === 'vulnerabilities' ? '#c084fc' : 'var(--text-muted)',
                fontSize: '0.84rem',
                padding: '6px 12px'
              }}
              onClick={() => setActiveTab('vulnerabilities')}
            >
              Vulnerability Queue ({vulnerabilities.length})
            </button>
            <button
              className="btn"
              style={{
                background: activeTab === 'health' ? 'rgba(16, 185, 129, 0.2)' : 'transparent',
                borderColor: activeTab === 'health' ? '#10b981' : 'transparent',
                color: activeTab === 'health' ? '#34d399' : 'var(--text-muted)',
                fontSize: '0.84rem',
                padding: '6px 12px'
              }}
              onClick={() => setActiveTab('health')}
            >
              Sensors & Telemetry
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {activeSessionId ? (
              <span className="badge badge-soc" style={{ fontSize: '0.72rem' }}>Target: {activeSessionId}</span>
            ) : (
              <button
                className="badge badge-blue"
                style={{ cursor: 'pointer', border: '1px solid #06b6d4' }}
                onClick={() => onNavigateRole && onNavigateRole('labs')}
              >
                Select Lab Sandbox ➜
              </button>
            )}
            {activeTab === 'alerts' && (
              <button
                id="btn-evaluate-rules"
                className="btn btn-primary"
                style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                onClick={handleEvaluateDetections}
                disabled={evaluating}
              >
                {evaluating ? "Evaluating..." : "Evaluate Rules"}
              </button>
            )}
          </div>
        </div>

        {/* Tab 1: Detection Alerts */}
        {activeTab === 'alerts' && (
          <div style={{ flex: 1, overflowY: 'auto', maxHeight: '580px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
              Alerts evaluate normalized telemetry events against active Sigma rules. Provenance indicates whether alerts stem from live traffic or lab simulation.
            </p>
            {detectionEvents.length === 0 ? (
              <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)', background: 'rgba(15, 23, 42, 0.4)', borderRadius: 'var(--radius-md)', border: '1px dashed var(--border-subtle)' }}>
                <div style={{ fontWeight: 600, color: '#94a3b8', marginBottom: '6px' }}>No Blue Team alerts triggered in this session</div>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', maxWidth: '440px', margin: '0 auto 14px' }}>
                  Run an adversary scenario in the Red Team Console, then click Evaluate Active Rules to generate detections.
                </p>
                <button
                  className="btn btn-outline"
                  style={{ fontSize: '0.78rem' }}
                  onClick={handleEvaluateDetections}
                  disabled={evaluating}
                >
                  {evaluating ? "Evaluating..." : "Scan & Evaluate Active Sigma Rules"}
                </button>
              </div>
            ) : (
              detectionEvents.map((al, idx) => (
                <div
                  key={al.event_id || idx}
                  style={{
                    background: 'rgba(6, 182, 212, 0.07)',
                    border: '1px solid rgba(6, 182, 212, 0.25)',
                    borderRadius: 'var(--radius-md)',
                    padding: '14px 18px',
                    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.2)'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="badge badge-covered">DETECTED</span>
                      <span className="badge" style={{ background: al.provenance === 'live' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)', color: al.provenance === 'live' ? '#34d399' : '#fbbf24', fontSize: '0.7rem' }}>
                        {(al.provenance || 'simulated').toUpperCase()}
                      </span>
                      <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.92rem' }}>
                        {al.action}
                      </span>
                    </div>
                    <span className={`badge ${al.severity === 'critical' ? 'badge-critical' : 'badge-gap'}`}>
                      {al.severity.toUpperCase()}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
                    Trigger ID: <code style={{ color: '#38bdf8', fontSize: '0.78rem' }}>{al.raw_payload?.triggering_event_id ? al.raw_payload.triggering_event_id.slice(0, 13) : 'telemetry'}</code> |
                    Rule: <span style={{ color: '#e2e8f0', fontFamily: 'var(--font-mono)' }}>{al.raw_payload?.rule_id || al.source_name}</span> |
                    Time: <span style={{ color: '#94a3b8' }}>{new Date(al.timestamp).toLocaleTimeString()}</span>
                  </div>

                  <div style={{ display: 'flex', gap: '10px', alignItems: 'center', fontSize: '0.78rem' }}>
                    <span className="badge badge-untested" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8' }}>
                      MITRE {al.mitre_technique}
                    </span>
                    {al.mitre_tactic && (
                      <span className="badge badge-untested" style={{ background: 'rgba(167, 139, 250, 0.15)', color: '#c084fc' }}>
                        {al.mitre_tactic}
                      </span>
                    )}
                    {al.raw_payload?.matched_action && (
                      <span style={{ color: 'var(--text-dim)', fontStyle: 'italic', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '320px' }}>
                        trigger: {al.raw_payload.matched_action}
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Tab 2: Vulnerability Queue */}
        {activeTab === 'vulnerabilities' && (
          <div style={{ flex: 1, overflowY: 'auto', maxHeight: '580px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
              Findings from real static configuration linting (Hadolint/Compose) and container image vulnerability scans (Trivy), linked to immutable image digests.
            </p>
            {vulnerabilities.length === 0 ? (
              <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)', background: 'rgba(15, 23, 42, 0.4)', borderRadius: 'var(--radius-md)' }}>
                No vulnerability findings registered. Upload a lab or build an image to generate scan evidence.
              </div>
            ) : (
              vulnerabilities.map((v, idx) => (
                <div
                  key={idx}
                  style={{
                    background: 'rgba(15, 23, 42, 0.6)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '12px 16px'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className={`badge ${v.severity === 'CRITICAL' ? 'badge-critical' : v.severity === 'HIGH' ? 'badge-red' : 'badge-soc'}`} style={{ fontSize: '0.72rem' }}>
                        {v.severity}
                      </span>
                      <span style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.88rem' }}>
                        {v.cve_id}
                      </span>
                      <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', fontSize: '0.68rem' }}>
                        {v.type === 'image_cve' ? 'IMAGE CVE' : 'STATIC POLICY'}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.74rem', color: 'var(--text-dim)' }}>
                      Lab: {v.lab_name}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.82rem', color: '#cbd5e1', marginBottom: '6px' }}>
                    {v.title}
                  </div>

                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                    <span>Pkg: <code style={{ color: '#38bdf8' }}>{v.package}</code></span>
                    <span>Version: <code style={{ color: '#94a3b8' }}>{v.installed_version}</code></span>
                    {v.fixed_version && v.fixed_version !== 'N/A' && (
                      <span>Fix: <code style={{ color: '#34d399' }}>{v.fixed_version}</code></span>
                    )}
                    <span>Source: <span style={{ color: '#a78bfa' }}>{v.evidence_source}</span></span>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Tab 3: Sensor & Telemetry Health */}
        {activeTab === 'health' && (
          <div style={{ flex: 1, overflowY: 'auto', maxHeight: '580px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
              Telemetry collector status and sensor pipeline health. In live mode, alerts require verified telemetry from these sources.
            </p>
            {sensorHealth && sensorHealth.sensors ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px' }}>
                {Object.entries(sensorHealth.sensors).map(([key, info]) => (
                  <div
                    key={key}
                    style={{
                      background: 'rgba(15, 23, 42, 0.6)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '14px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.88rem' }}>
                        {key.replace(/_/g, ' ').toUpperCase()}
                      </span>
                      <span
                        className="badge"
                        style={{
                          background: (info.connected || info.status === 'active') ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                          color: (info.connected || info.status === 'active') ? '#34d399' : '#fbbf24',
                          fontSize: '0.72rem'
                        }}
                      >
                        {info.connected ? 'CONNECTED' : (info.status || info.mode || 'FALLBACK').toUpperCase()}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      Mode: <span style={{ color: '#38bdf8' }}>{info.mode || info.status}</span>
                    </div>
                    {info.broker && (
                      <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                        Endpoint: {info.broker}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)' }}>Querying sensor health...</div>
            )}
          </div>
        )}
      </div>

      {/* Right Column: Sigma Rule Editor & Compiler */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <h3 style={{ color: '#a78bfa', display: 'flex', alignItems: 'center', gap: '8px' }}>
            Sigma Rule Compiler
          </h3>
          <span className="badge badge-covered">{rules.length} Active Rules</span>
        </div>

        {/* Rule selector pills */}
        <div style={{ display: 'flex', gap: '8px', overflowX: 'auto', paddingBottom: '8px', marginBottom: '14px' }}>
          {rules.map(r => (
            <button
              key={r.id}
              onClick={() => handleSelectRule(r)}
              style={{
                background: selectedRule?.id === r.id ? 'rgba(167, 139, 250, 0.25)' : 'rgba(15, 23, 42, 0.8)',
                border: `1px solid ${selectedRule?.id === r.id ? '#a78bfa' : 'var(--border-subtle)'}`,
                color: selectedRule?.id === r.id ? '#ffffff' : '#94a3b8',
                padding: '5px 12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.78rem',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                fontWeight: 600
              }}
            >
              {r.mitre_technique || r.id}
            </button>
          ))}
        </div>

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <textarea
            id="textarea-sigma-yaml"
            value={editorYaml}
            onChange={(e) => setEditorYaml(e.target.value)}
            style={{
              flex: 1,
              minHeight: '340px',
              background: '#05070c',
              border: '1px solid #1e293b',
              borderRadius: 'var(--radius-md)',
              color: '#34d399',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.82rem',
              padding: '14px',
              lineHeight: 1.5,
              outline: 'none',
              resize: 'vertical'
            }}
          />

          {validationResult && (
            <div style={{
              padding: '10px 14px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8rem',
              background: validationResult.valid ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
              border: `1px solid ${validationResult.valid ? '#10b981' : '#ef4444'}`,
              color: validationResult.valid ? '#34d399' : '#f87171'
            }}>
              {validationResult.valid ? (
                <div>
                  <strong>✔ Validated via pySigma:</strong> Rule '{validationResult.title || 'Rule'}' is valid.
                </div>
              ) : (
                <div>
                  <strong>✖ Validation Error:</strong> {validationResult.error}
                </div>
              )}
            </div>
          )}

          <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', marginTop: '6px' }}>
            <button
              id="btn-validate-sigma"
              className="btn btn-outline"
              onClick={handleValidateRule}
              style={{ fontSize: '0.82rem' }}
            >
              Verify Syntax
            </button>
            <button
              id="btn-deploy-sigma"
              className="btn btn-primary"
              onClick={handleSaveRule}
              style={{ fontSize: '0.82rem' }}
            >
              Save & Hot-Deploy Rule
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

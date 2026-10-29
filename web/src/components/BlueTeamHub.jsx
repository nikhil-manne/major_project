import React, { useState, useEffect } from 'react';

export default function BlueTeamHub({ activeSessionId, events, onRefreshEvents, onNavigateRole }) {
  const [rules, setRules] = useState([]);
  const [alerts, setAlerts] = useState([]);
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

  useEffect(() => {
    fetchRules();
    fetchAlerts();
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
    <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 0.9fr', gap: '24px' }}>
      {/* Left Column: Detection Alerts */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h3 style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '8px' }}>
              Detection Alerts
            </h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              The backend evaluates stored normalized events against local rules. Falco/Suricata data appears only when those collectors are configured and their events are ingested.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {activeSessionId ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="badge badge-soc">Target: {activeSessionId}</span>
                {onNavigateRole && (
                  <button
                    className="btn btn-secondary"
                    style={{ padding: '3px 8px', fontSize: '0.72rem' }}
                    onClick={() => onNavigateRole('labs')}
                    title="Switch target sandbox in Common Labs"
                  >
                    Switch
                  </button>
                )}
              </div>
            ) : (
              <button
                className="badge badge-blue"
                style={{ cursor: 'pointer', border: '1px solid #06b6d4' }}
                onClick={() => onNavigateRole && onNavigateRole('labs')}
                title="Click to launch or select an active sandbox in Common Labs"
              >
                No Sandbox · Select in Labs ➜
              </button>
            )}
            <button
              id="btn-evaluate-rules"
              className="btn btn-primary"
              style={{ padding: '7px 14px', fontSize: '0.82rem' }}
              onClick={handleEvaluateDetections}
              disabled={evaluating}
            >
              {evaluating ? "Evaluating..." : "Evaluate Active Rules"}
            </button>
          </div>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', maxHeight: '580px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {detectionEvents.length === 0 ? (
            <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)', background: 'rgba(15, 23, 42, 0.4)', borderRadius: 'var(--radius-md)', border: '1px dashed var(--border-subtle)' }}>
              <div style={{ fontWeight: 600, color: '#94a3b8', marginBottom: '6px' }}>No Blue Team alerts triggered in this session</div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', maxWidth: '440px', margin: '0 auto 14px' }}>
                If you ran manual probes that <strong>bypassed detection</strong>, they will not trigger alerts here. Instead, check the <strong>MITRE ATT&CK Matrix</strong> to view them as <strong>Detection Gaps</strong> (red), or run an automated playbook to trigger detections.
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
                    <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.92rem' }}>
                      {al.action}
                    </span>
                  </div>
                  <span className={`badge ${al.severity === 'critical' ? 'badge-critical' : 'badge-gap'}`}>
                    {al.severity.toUpperCase()}
                  </span>
                </div>

                <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
                  Rule/source: <span style={{ color: '#e2e8f0', fontFamily: 'var(--font-mono)' }}>{al.source_name}</span> |
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

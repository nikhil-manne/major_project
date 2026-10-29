import React, { useState, useEffect } from 'react';

export default function RedTeamConsole({ activeSessionId, events, onRefreshEvents, onNavigateRole }) {
  const [scenarios, setScenarios] = useState([]);
  const [selectedScenario, setSelectedScenario] = useState('');
  const [executing, setExecuting] = useState(false);
  const [commandInput, setCommandInput] = useState('');
  const [terminalHistory, setTerminalHistory] = useState([
    "=== Red Team Console ===",
    "No session selected. Create a session in Labs before running a scenario.",
    "Execution mode and outcomes are shown after each request; simulation output is not live telemetry.",
    ""
  ]);

  useEffect(() => {
    fetch('/api/v1/attack/scenarios')
      .then(res => res.json())
      .then(data => {
        setScenarios(data);
        if (data.length > 0) setSelectedScenario(data[0].id);
      })
      .catch(() => {});
  }, []);

  const currentSession = activeSessionId || '';
  const sessionSelected = Boolean(currentSession);

  const handleLaunchScenario = async () => {
    if (!selectedScenario) return;
    if (!sessionSelected) {
      setTerminalHistory(prev => [...prev, '[-] Select or launch a session in Labs before running a scenario.']);
      return;
    }
    setExecuting(true);
    setTerminalHistory(prev => [...prev, `\n\x1b[31;1m[*] Launching automated adversary playbook: ${selectedScenario}...\x1b[0m`]);

    try {
      const res = await fetch('/api/v1/attack/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_id: selectedScenario,
          session_id: currentSession,
          operator: 'red1'
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail?.message || data.detail || `HTTP ${res.status}`);
      setTerminalHistory(prev => [
        ...prev,
        `[+] Playbook submitted: ${data.scenario}`,
        `[+] Mode: ${data.execution_mode} | Steps: ${data.steps_executed} | Live: ${data.live_steps} | Simulated: ${data.simulated_steps} | Blocked: ${data.blocked_steps}`,
        `[+] MITRE Technique: ${data.technique}`
      ]);
      onRefreshEvents();
    } catch (err) {
      setTerminalHistory(prev => [...prev, `[-] Error executing playbook: ${err.message}`]);
    } finally {
      setExecuting(false);
    }
  };

  const handleCommandSubmit = async (e) => {
    e.preventDefault();
    if (!commandInput.trim()) return;
    if (!sessionSelected) {
      setTerminalHistory(prev => [...prev, '[-] Select or launch a session in Labs before executing a command.']);
      return;
    }

    const cmd = commandInput.trim();
    setCommandInput('');
    setTerminalHistory(prev => [...prev, `redteam@toolbox:~$ ${cmd}`]);

    try {
      const res = await fetch('/api/v1/attack/terminal/execute-command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: currentSession,
          command: cmd,
          operator: 'red1'
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail?.message || data.detail || `HTTP ${res.status}`);
      setTerminalHistory(prev => [...prev, data.output, `[Mode: ${data.execution_mode} | Outcome: ${data.outcome} | Technique: ${data.mitre_technique}]`, '']);
      onRefreshEvents();
    } catch (err) {
      setTerminalHistory(prev => [...prev, `[-] Command execution failed: ${err.message}`]);
    }
  };

  const attackEvents = activeSessionId ? events.filter(e => e.source_type === 'attack' && e.session_id === activeSessionId) : [];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
      {/* Left Column: Playbook Controls & Interactive Terminal */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {/* Playbook Launcher Card */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <h3 style={{ color: '#f87171', display: 'flex', alignItems: 'center', gap: '8px' }}>
              Adversary Emulation Playbooks
            </h3>
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
                    Switch Sandbox
                  </button>
                )}
              </div>
            ) : (
              <button
                className="badge badge-red"
                style={{ cursor: 'pointer', border: '1px solid #ef4444' }}
                onClick={() => onNavigateRole && onNavigateRole('labs')}
                title="Click to launch or select an active sandbox in Common Labs"
              >
                No Sandbox · Select in Labs ➜
              </button>
            )}
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <select
              id="select-scenario"
              value={selectedScenario}
              onChange={(e) => setSelectedScenario(e.target.value)}
              style={{
                flex: 1,
                background: '#090d16',
                border: '1px solid var(--border-subtle)',
                color: '#ffffff',
                padding: '10px 14px',
                borderRadius: 'var(--radius-md)',
                outline: 'none',
                fontFamily: 'var(--font-sans)',
                fontSize: '0.9rem'
              }}
            >
              {scenarios.map(s => (
                <option key={s.id} value={s.id}>
                  {s.id}: {s.name} ({s.mitre_technique})
                </option>
              ))}
            </select>

            <button
              id="btn-execute-scenario"
              className="btn btn-danger"
              onClick={handleLaunchScenario}
              disabled={executing}
            >
              {executing ? "Executing..." : "Execute Attack"}
            </button>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '10px' }}>
            Scenario runs are labelled simulated or live. Event-stream delivery depends on the configured backend services.
          </p>
        </div>

        {/* Terminal Window */}
        <div className="terminal-window">
          <div className="terminal-header">
            <div className="terminal-dots">
              <div className="dot red"></div>
              <div className="dot yellow"></div>
              <div className="dot green"></div>
            </div>
            <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              Command Runner API (session-{activeSessionId || 'no-session'})
            </span>
            <span className="badge badge-untested" style={{ fontSize: '0.7rem' }}>Recording: integration-dependent</span>
          </div>

          <div className="terminal-body" id="red-terminal-body">
            {terminalHistory.map((line, idx) => (
              <div key={idx} style={{ whiteSpace: 'pre-wrap' }}>{line}</div>
            ))}
          </div>

          <form onSubmit={handleCommandSubmit} className="terminal-input-bar">
            <span className="terminal-prompt">redteam@toolbox:~$</span>
            <input
              id="input-terminal-command"
              type="text"
              className="terminal-input"
              placeholder="e.g. nmap -sV target-pod or msfconsole..."
              value={commandInput}
              onChange={(e) => setCommandInput(e.target.value)}
            />
          </form>
        </div>
      </div>

      {/* Right Column: Live Attack Telemetry Stream */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            Attack Event Feed
          </h3>
          <span className="badge badge-gap">{attackEvents.length} Actions Recorded</span>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', maxHeight: '560px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {attackEvents.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-dim)' }}>
              No attack actions executed in this session yet. Launch a playbook or enter a command in the terminal.
            </div>
          ) : (
            attackEvents.map((ev, i) => (
              <div
                key={ev.event_id || i}
                style={{
                  background: 'rgba(239, 68, 68, 0.06)',
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                  borderRadius: 'var(--radius-md)',
                  padding: '12px 16px'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="badge badge-gap">{ev.source_name}</span>
                    <span style={{ fontWeight: 600, fontSize: '0.88rem' }}>{ev.actor}</span>
                  </div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#fca5a5', marginBottom: '6px' }}>
                  {ev.action}
                </div>
                <div style={{ display: 'flex', gap: '8px', fontSize: '0.75rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Technique:</span>
                  <span style={{ color: '#38bdf8', fontWeight: 600 }}>{ev.mitre_technique || 'N/A'}</span>
                  <span style={{ color: 'var(--text-muted)', marginLeft: '12px' }}>Tactic:</span>
                  <span style={{ color: '#a78bfa' }}>{ev.mitre_tactic || 'N/A'}</span>
                  <span className="badge badge-untested">{ev.raw_payload?.execution_mode || (ev.raw_payload?.executed_live === true ? 'live' : 'mode unreported')}</span>
                  {ev.replay && <span className="badge badge-untested" style={{ marginLeft: 'auto' }}>REPLAY</span>}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

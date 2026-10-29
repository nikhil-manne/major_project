import React, { useState, useEffect } from 'react';

export default function ReplayStudio({ activeSessionId, onRefreshEvents }) {
  const [archivedSessions, setArchivedSessions] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState(activeSessionId || '');
  const [manifest, setManifest] = useState(null);
  const [timelineData, setTimelineData] = useState([]);
  const [currentTimeOffset, setCurrentTimeOffset] = useState(0);
  const [maxTimeOffset, setMaxTimeOffset] = useState(10);
  const [replaying, setReplaying] = useState(false);
  const [replayOutcome, setReplayOutcome] = useState(null);
  const [isPlaying, setIsPlaying] = useState(false);

  useEffect(() => {
    fetch('/api/v1/replay/sessions')
      .then(res => res.json())
      .then(data => {
        setArchivedSessions(data);
        if (data.length > 0 && !selectedSessionId) {
          setSelectedSessionId(data[0].session_id);
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedSessionId) return;

    fetch(`/api/v1/replay/manifest/${selectedSessionId}`)
      .then(res => res.json())
      .then(data => setManifest(data))
      .catch(() => setManifest(null));

    fetch(`/api/v1/replay/timeline/${selectedSessionId}`)
      .then(res => res.json())
      .then(data => {
        setTimelineData(data.timeline || []);
        setMaxTimeOffset(Math.max(10, data.duration_sec || 10));
        setCurrentTimeOffset(0);
      })
      .catch(() => setTimelineData([]));
  }, [selectedSessionId]);

  // Timeline playback timer
  useEffect(() => {
    let timer;
    if (isPlaying) {
      timer = setInterval(() => {
        setCurrentTimeOffset(prev => {
          if (prev >= maxTimeOffset) {
            setIsPlaying(false);
            return maxTimeOffset;
          }
          return Math.round((prev + 0.5) * 10) / 10;
        });
      }, 500);
    }
    return () => clearInterval(timer);
  }, [isPlaying, maxTimeOffset]);

  const handleExecuteRegressionTest = async () => {
    if (!selectedSessionId) return;
    setReplaying(true);
    try {
      const res = await fetch(`/api/v1/replay/execute/${selectedSessionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: selectedSessionId, test_detection_rules: true })
      });
      const data = await res.json();
      setReplayOutcome(data);
      onRefreshEvents();
    } catch (err) {
      console.error(err);
    } finally {
      setReplaying(false);
    }
  };

  const visibleEvents = timelineData.filter(pt => pt.time_offset_sec <= currentTimeOffset);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner: Session Picker & Regression Test Runner */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <h2 style={{ fontSize: '1.4rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
              Session Recording & Detection Regression Studio
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '4px' }}>
              Session events and available terminal records are archived. Network capture status is explicitly shown because real packet data depends on a configured sandbox sensor and object store. Replay recorded attack events to regression-test Sigma rules.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <select
              id="select-replay-session"
              value={selectedSessionId}
              onChange={(e) => setSelectedSessionId(e.target.value)}
              style={{
                background: '#090d16',
                border: '1px solid var(--border-subtle)',
                color: '#ffffff',
                padding: '8px 14px',
                borderRadius: 'var(--radius-md)',
                outline: 'none',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.84rem'
              }}
            >
              {archivedSessions.map(s => (
                <option key={s.session_id} value={s.session_id}>
                  {s.session_id} ({s.target_image || 'target'}) - {s.total_events} events
                </option>
              ))}
            </select>

            <button
              id="btn-run-regression"
              className="btn btn-primary"
              onClick={handleExecuteRegressionTest}
              disabled={replaying}
              style={{ fontSize: '0.82rem' }}
            >
              {replaying ? "Replaying Attack..." : "Replay Attack As Regression Test"}
            </button>
          </div>
        </div>

        {replayOutcome && (
          <div style={{
            marginTop: '16px',
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid #10b981',
            borderRadius: 'var(--radius-md)',
            padding: '14px',
            fontSize: '0.85rem'
          }}>
            <h4 style={{ color: '#34d399', marginBottom: '6px' }}>Replay Operation Finished</h4>
            <div>
              Re-emitted <strong>{replayOutcome.attacks_re_emitted}</strong> attack events.
              Newly fired <strong>{replayOutcome.detections_triggered}</strong> detections with active Sigma rules.
            </div>
            <div style={{ marginTop: '6px', fontSize: '0.78rem', color: '#94a3b8' }}>
              Techniques Tested: {replayOutcome.regression_test_summary?.techniques_tested.join(', ') || 'None'}
            </div>
          </div>
        )}
      </div>

      {/* Synchronized Timeline Scrubber */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <button
              id="btn-play-pause-replay"
              className="btn btn-outline"
              onClick={() => setIsPlaying(!isPlaying)}
              style={{ padding: '6px 16px', fontSize: '0.82rem' }}
            >
              {isPlaying ? "⏸ Pause" : "▶ Play Timeline"}
            </button>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', color: '#38bdf8' }}>
              T+ {currentTimeOffset.toFixed(1)}s / {maxTimeOffset.toFixed(1)}s
            </span>
          </div>

          <span className="badge badge-untested">
            {visibleEvents.length} / {timelineData.length} events displayed
          </span>
        </div>

        {/* Range Slider Scrubber */}
        <input
          id="replay-time-slider"
          type="range"
          min="0"
          max={maxTimeOffset}
          step="0.5"
          value={currentTimeOffset}
          onChange={(e) => {
            setIsPlaying(false);
            setCurrentTimeOffset(parseFloat(e.target.value));
          }}
          style={{
            width: '100%',
            accentColor: '#06b6d4',
            cursor: 'pointer',
            marginBottom: '20px'
          }}
        />

        {/* Synchronized Events Stream */}
        <div style={{
          maxHeight: '440px',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px'
        }}>
          {visibleEvents.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-dim)' }}>
              Drag the scrubber slider or hit "Play" to step through the session recording timeline.
            </div>
          ) : (
            visibleEvents.map((pt, i) => (
              <div
                key={pt.event_id || i}
                style={{
                  background: pt.source_type === 'attack' ? 'rgba(239, 68, 68, 0.08)' : (pt.source_type === 'detection' ? 'rgba(6, 182, 212, 0.08)' : 'rgba(255,255,255,0.03)'),
                  border: `1px solid ${pt.source_type === 'attack' ? 'rgba(239, 68, 68, 0.3)' : (pt.source_type === 'detection' ? 'rgba(6, 182, 212, 0.3)' : 'var(--border-subtle)')}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: '10px 14px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  fontSize: '0.84rem'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', fontSize: '0.78rem', minWidth: '50px' }}>
                    +{pt.time_offset_sec}s
                  </span>
                  <span className={`badge ${pt.source_type === 'attack' ? 'badge-gap' : (pt.source_type === 'detection' ? 'badge-covered' : 'badge-untested')}`}>
                    {pt.source_type.toUpperCase()}
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: '#f1f5f9' }}>
                    {pt.action}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {pt.mitre_technique && (
                    <span className="badge badge-untested" style={{ fontSize: '0.72rem' }}>
                      {pt.mitre_technique}
                    </span>
                  )}
                  {pt.replay && (
                    <span className="badge badge-untested" style={{ color: '#c084fc', borderColor: '#c084fc' }}>
                      REPLAY
                    </span>
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

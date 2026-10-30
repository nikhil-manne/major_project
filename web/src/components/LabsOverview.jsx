import React, { useState, useEffect } from 'react';

export default function LabsOverview({ user, activeSessionId, onSelectSession, onNavigateRole }) {
  const [labs, setLabs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [labName, setLabName] = useState('');
  const [labDescription, setLabDescription] = useState('');
  const [expandedLabId, setExpandedLabId] = useState(null);
  const [launchingLabId, setLaunchingLabId] = useState(null);
  const [buildingLabId, setBuildingLabId] = useState(null);
  const [destroyingSessionId, setDestroyingSessionId] = useState(null);
  const [notification, setNotification] = useState(null);

  const isAdmin = user?.role === 'admin';

  const showNotice = (msg, type = 'info') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 6000);
  };

  const handleBuildLab = async (labId, e) => {
    if (e) e.stopPropagation();
    if (!isAdmin) {
      showNotice("Only Administrators can trigger image builds.", "error");
      return;
    }
    setBuildingLabId(labId);
    showNotice(`Triggering container image build for lab '${labId}'...`, "info");
    try {
      const res = await fetch(`/api/v1/labs/${labId}/build`, {
        method: "POST"
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail?.message || data.detail || "Build request failed");
      }
      if (data.status === 'image_built' || data.status === 'ready') {
        showNotice(`Lab '${data.name}' built successfully! Digest: ${data.image_digest?.slice(0, 19)}...`, "success");
      } else {
        showNotice(`Build outcome: ${data.status} · ${data.build_logs?.slice(0, 100) || ''}`, "warning");
      }
      fetchLabs();
    } catch (err) {
      showNotice(`Build error: ${err.message}`, "error");
    } finally {
      setBuildingLabId(null);
    }
  };

  const fetchLabs = () => {
    setLoading(true);
    fetch('/api/v1/labs')
      .then(res => res.json())
      .then(data => {
        setLabs(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch(err => {
        console.error("Failed to load labs:", err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchLabs();
  }, []);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      if (!labName) {
        setLabName(file.name.replace(/\.[^/.]+$/, "").replace(/[-_]/g, " ") + " Lab");
      }
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      if (!labName) {
        setLabName(file.name.replace(/\.[^/.]+$/, "").replace(/[-_]/g, " ") + " Lab");
      }
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!isAdmin) {
      showNotice("Only Administrators are permitted to upload Dockerfiles or create labs.", "error");
      return;
    }
    if (!selectedFile) {
      showNotice("Please select a Dockerfile or docker-compose.yml file", "warning");
      return;
    }
    if (!labName.trim()) {
      showNotice("Please provide a name for this Lab", "warning");
      return;
    }

    setUploading(true);
    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("name", labName);
    formData.append("description", labDescription);

    try {
      const res = await fetch("/api/v1/labs", {
        method: "POST",
        body: formData
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail?.message || data.detail || "Failed to upload Lab");
      }

      showNotice(`Common Lab '${data.name}' registered successfully! It is now available to all teams.`, "success");
      setSelectedFile(null);
      setLabName('');
      setLabDescription('');
      fetchLabs();
    } catch (err) {
      showNotice(`Upload error: ${err.message}`, "error");
    } finally {
      setUploading(false);
    }
  };

  const handleLaunchSession = async (labId, labName) => {
    setLaunchingLabId(labId);
    showNotice(`Provisioning an isolated sandbox for '${labName}'...`, "info");
    try {
      const res = await fetch(`/api/v1/labs/${labId}/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ttl_minutes: 45 })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail?.message || data.detail || "Sandbox launch failed");
      }

      const mode = data.isolation?.execution_mode || 'isolated';
      showNotice(`Sandbox '${data.session_id}' created successfully (mode: ${mode})! You can run multiple sandboxes concurrently.`, "success");
      
      // Immediately select this sandbox across all modules
      if (onSelectSession) {
        onSelectSession(data.session_id);
      }
      
      // Auto expand this lab's sandboxes drawer so user sees their new instance
      setExpandedLabId(labId);
      fetchLabs();
    } catch (err) {
      showNotice(`Launch failed: ${err.message}`, "error");
    } finally {
      setLaunchingLabId(null);
    }
  };

  const handleDestroySandbox = async (sessionId, e) => {
    if (e) e.stopPropagation();
    if (!window.confirm(`Destroy and teardown sandbox instance '${sessionId}'?`)) return;
    setDestroyingSessionId(sessionId);
    try {
      const res = await fetch(`/api/v1/sessions/${sessionId}`, { method: "DELETE" });
      if (res.ok) {
        showNotice(`Sandbox '${sessionId}' destroyed.`, "info");
        if (activeSessionId === sessionId && onSelectSession) {
          onSelectSession(null);
        }
        fetchLabs();
      } else {
        const data = await res.json().catch(() => ({}));
        showNotice(`Failed to destroy sandbox: ${data.detail || res.status}`, "error");
      }
    } catch (err) {
      showNotice(`Error destroying sandbox: ${err.message}`, "error");
    } finally {
      setDestroyingSessionId(null);
    }
  };

  const handleArchiveLab = async (labId) => {
    if (!isAdmin) {
      showNotice("Only Administrators can archive labs.", "error");
      return;
    }
    if (!window.confirm("Archive this Common Lab definition? Existing session history will be preserved.")) return;
    try {
      const res = await fetch(`/api/v1/labs/${labId}`, { method: "DELETE" });
      if (res.ok) {
        showNotice("Lab archived from common catalog", "info");
        fetchLabs();
      } else {
        const err = await res.json();
        showNotice(err.detail || "Failed to archive lab", "error");
      }
    } catch (err) {
      showNotice("Failed to archive lab: " + err.message, "error");
    }
  };

  // Aggregates
  const totalActiveSessions = labs.reduce((acc, l) => acc + (l.active_session_count || 0), 0);
  const totalCommonLabs = labs.length;

  // Active Lab Name if activeSessionId is known
  let activeLabName = 'No active sandbox';
  if (activeSessionId) {
    for (const l of labs) {
      if (l.active_sessions?.some(s => s.session_id === activeSessionId)) {
        activeLabName = l.name;
        break;
      }
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px', maxWidth: '1440px', margin: '0 auto', paddingBottom: '60px' }}>
      
      {/* Banner & High-level Metrics */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
        <div>
          <h1 style={{ fontSize: '2rem', display: 'flex', alignItems: 'center', gap: '12px' }}>
            Common Labs & Multi-Sandbox Workspace
          </h1>
          <p style={{ color: 'var(--text-muted)', marginTop: '4px', maxWidth: '720px' }}>
            Universal enterprise lab catalog shared across Red, Blue, and SOC teams. Switch between existing common labs, inspect target images, and launch multiple isolated sandboxes of any lab concurrently.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '16px' }}>
          <div className="glass-panel" style={{ padding: '14px 20px', textAlign: 'center', minWidth: '120px' }}>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#38bdf8' }}>{totalCommonLabs}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Common Labs</div>
          </div>
          <div className="glass-panel" style={{ padding: '14px 20px', textAlign: 'center', minWidth: '130px' }}>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#10b981' }}>{totalActiveSessions}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Running Sandboxes</div>
          </div>
          <div className="glass-panel" style={{ padding: '14px 20px', textAlign: 'center', minWidth: '120px' }}>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: '#a855f7' }}>Shared</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Cross-Team Access</div>
          </div>
        </div>
      </div>

      {/* Notification Banner */}
      {notification && (
        <div style={{
          padding: '12px 20px',
          borderRadius: 'var(--radius-md)',
          background: notification.type === 'error' ? 'rgba(239, 68, 68, 0.2)' : notification.type === 'success' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(6, 182, 212, 0.2)',
          border: `1px solid ${notification.type === 'error' ? '#ef4444' : notification.type === 'success' ? '#10b981' : '#06b6d4'}`,
          color: '#ffffff',
          fontWeight: 600,
          fontSize: '0.9rem',
          display: 'flex',
          alignItems: 'center',
          gap: '10px'
        }}>
          <span>{notification.msg}</span>
        </div>
      )}

      {/* Active Sandbox Context & Quick Switcher Strip */}
      <div className="glass-panel" style={{
        padding: '16px 20px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '14px',
        background: 'rgba(15, 23, 42, 0.85)',
        border: '1px solid rgba(6, 182, 212, 0.3)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Current Global Active Target
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
              {activeSessionId ? (
                <>
                  <span style={{ color: '#10b981' }}>●</span>
                  <code style={{ color: '#38bdf8' }}>{activeSessionId}</code>
                  <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>({activeLabName})</span>
                </>
              ) : (
                <span style={{ color: 'var(--text-dim)' }}>None selected — click "Target" on any active sandbox below or launch a new one</span>
              )}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {user?.role === 'red' && onNavigateRole && (
            <button
              className="btn btn-primary"
              style={{ padding: '8px 16px', fontSize: '0.84rem', background: '#ef4444', borderColor: '#ef4444' }}
              onClick={() => onNavigateRole('red')}
            >
              Go to Red Team Console
            </button>
          )}
          {user?.role === 'blue' && onNavigateRole && (
            <button
              className="btn btn-primary"
              style={{ padding: '8px 16px', fontSize: '0.84rem', background: '#06b6d4', borderColor: '#06b6d4' }}
              onClick={() => onNavigateRole('blue')}
            >
              Go to Blue Team Hub
            </button>
          )}
          {user?.role === 'soc' && onNavigateRole && (
            <button
              className="btn btn-primary"
              style={{ padding: '8px 16px', fontSize: '0.84rem', background: '#10b981', borderColor: '#10b981' }}
              onClick={() => onNavigateRole('soc')}
            >
              Go to SOC Desk
            </button>
          )}
          {isAdmin && (
            <span className="badge" style={{ background: 'rgba(168, 85, 247, 0.2)', color: '#c084fc', border: '1px solid #a855f7' }}>
              Admin Access Enabled
            </span>
          )}
        </div>
      </div>

      {/* Role-Gated Upload Section: ONLY Admin Can Upload Dockerfiles / Create Labs */}
      {isAdmin ? (
        <div className="glass-panel" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '1.15rem', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            Upload New Common Lab Environment (Admin Only)
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '18px' }}>
            Upload a Dockerfile or docker-compose.yml to register a new common environment. Once uploaded, it becomes immediately accessible to Red, Blue, and SOC teams to launch sandboxes.
          </p>

          <form onSubmit={handleUploadSubmit}>
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              style={{
                border: `2px dashed ${dragActive ? '#06b6d4' : 'var(--border-subtle)'}`,
                borderRadius: 'var(--radius-md)',
                background: dragActive ? 'rgba(6, 182, 212, 0.08)' : 'rgba(0, 0, 0, 0.2)',
                padding: '30px 20px',
                textAlign: 'center',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                marginBottom: '20px'
              }}
              onClick={() => document.getElementById('lab-file-input').click()}
            >
              <input
                id="lab-file-input"
                type="file"
                accept=".dockerfile,Dockerfile,.yaml,.yml,.zip,.tar,.gz,.tar.gz,.tgz"
                style={{ display: 'none' }}
                onChange={handleFileChange}
              />

              {selectedFile ? (
                <div>
                  <span className="badge badge-soc" style={{ fontSize: '0.9rem', padding: '6px 14px' }}>
                    {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
                  </span>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '8px' }}>
                    Click or drag another file or archive to replace
                  </p>
                </div>
              ) : (
                <div>
                  <p style={{ fontWeight: 600, fontSize: '1rem', color: 'var(--text-main)' }}>
                    Drag & Drop <span style={{ color: '#06b6d4' }}>Dockerfile</span>, <span style={{ color: '#38bdf8' }}>docker-compose.yml</span>, or <span style={{ color: '#a855f7' }}>Context Archive (.zip / .tar.gz)</span>
                  </p>
                  <p style={{ fontSize: '0.82rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                    or click to browse from your computer (safe traversal checked, max 25MB)
                  </p>
                </div>
              )}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Lab Display Name *
                </label>
                <input
                  type="text"
                  className="input"
                  style={{ width: '100%' }}
                  placeholder="e.g. Vulnerable Apache Struts E-Commerce v2"
                  value={labName}
                  onChange={(e) => setLabName(e.target.value)}
                  required
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
                  Description / Attack Surface Notes
                </label>
                <input
                  type="text"
                  className="input"
                  style={{ width: '100%' }}
                  placeholder="e.g. Demonstrates CVE-2017-5638 RCE and remote shell lateral movement"
                  value={labDescription}
                  onChange={(e) => setLabDescription(e.target.value)}
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => { setSelectedFile(null); setLabName(''); setLabDescription(''); }}
                disabled={uploading}
              >
                Reset
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={uploading || !selectedFile}
                style={{ minWidth: '180px' }}
              >
                {uploading ? "Publishing Lab..." : "Upload & Publish Common Lab"}
              </button>
            </div>
          </form>
        </div>
      ) : (
        /* Non-Admin Informational Banner */
        <div className="glass-panel" style={{
          padding: '20px 24px',
          background: 'rgba(6, 182, 212, 0.05)',
          border: '1px solid rgba(6, 182, 212, 0.25)',
          display: 'flex',
          alignItems: 'center',
          gap: '16px'
        }}>
          <div>
            <h3 style={{ fontSize: '1.05rem', color: '#38bdf8', marginBottom: '4px' }}>
              Common Enterprise Lab Repository — Admin Managed
            </h3>
            <p style={{ fontSize: '0.86rem', color: 'var(--text-muted)', lineHeight: 1.45 }}>
              Lab configurations and Docker environments are managed centrally by Administrators. As a member of the <strong style={{ color: '#f8fafc' }}>{user?.role_label || user?.role}</strong>, you have full access to switch between all available common labs below, inspect target configurations, and spawn multiple concurrent sandboxes as needed for your team exercises.
            </p>
          </div>
        </div>
      )}

      {/* Common Labs Grid */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h2 style={{ fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>Available Common Labs</span>
              <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8' }}>{labs.length}</span>
            </h2>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-dim)', marginTop: '2px' }}>
              Select any lab below to switch targets or spawn new isolated sandboxes.
            </p>
          </div>

          <button className="btn btn-secondary" style={{ padding: '6px 14px', fontSize: '0.82rem' }} onClick={fetchLabs}>
            Refresh Catalog
          </button>
        </div>

        {loading ? (
          <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
            Loading common lab catalog...
          </div>
        ) : labs.length === 0 ? (
          <div className="glass-panel" style={{ padding: '50px', textAlign: 'center' }}>
            <h3>No Common Labs Found</h3>
            <p style={{ color: 'var(--text-muted)', marginTop: '6px', maxWidth: '400px', margin: '6px auto 16px auto' }}>
              {isAdmin ? "Upload a Dockerfile above or trigger the demo simulation to seed challenge labs." : "An administrator will publish common lab environments for your exercises."}
            </p>
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: '20px' }}>
            {labs.map(lab => {
              const scan = lab.safety_scan_result || {};
              const scanPassed = scan.passed === true;
              const isExpanded = expandedLabId === lab.id;
              const activeCount = lab.active_session_count || 0;

              return (
                <div
                  key={lab.id}
                  className="glass-panel"
                  style={{
                    padding: '20px',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    transition: 'border-color 0.2s ease, transform 0.2s ease',
                    position: 'relative',
                    borderColor: lab.active_sessions?.some(s => s.session_id === activeSessionId) ? 'rgba(6, 182, 212, 0.6)' : undefined,
                  }}
                >
                  {/* Top Bar: Name & Badges */}
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px', marginBottom: '8px' }}>
                      <h3 style={{ fontSize: '1.1rem', color: '#f8fafc', lineHeight: 1.3 }}>{lab.name}</h3>
                      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                        <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', fontSize: '0.72rem' }}>
                          COMMON
                        </span>
                        <span className={`badge ${lab.status === 'built' ? 'badge-soc' : lab.status === 'failed' ? 'badge-red' : 'badge-soc'}`}>
                          {lab.status.toUpperCase()}
                        </span>
                      </div>
                    </div>

                    <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', marginBottom: '16px', minHeight: '38px', lineHeight: 1.4 }}>
                      {lab.description || "Standing multi-team challenge lab environment."}
                    </p>

                    {/* Metadata Box */}
                    <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '10px 14px', borderRadius: 'var(--radius-sm)', marginBottom: '16px', fontSize: '0.8rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                        <span style={{ color: 'var(--text-dim)' }}>Content Hash:</span>
                        <code style={{ color: '#94a3b8', fontSize: '0.78rem' }}>{lab.content_hash ? lab.content_hash.slice(0, 12) : (lab.id || 'N/A')}</code>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                        <span style={{ color: 'var(--text-dim)' }}>Image Digest:</span>
                        <code style={{ color: lab.image_digest ? '#10b981' : '#f59e0b', fontSize: '0.78rem' }}>
                          {lab.image_digest ? `${lab.image_digest.slice(0, 18)}...` : (lab.image_tag || 'Not Built Yet')}
                        </code>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                        <span style={{ color: 'var(--text-dim)' }}>Policy Gate:</span>
                        <span style={{ color: scanPassed ? '#10b981' : '#ef4444', fontWeight: 600 }}>
                          {scanPassed ? 'PASSED · SCREENED' : 'POLICY BLOCKED'}
                        </span>
                      </div>
                      {lab.vulnerability_scan_result?.summary && (
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                          <span style={{ color: 'var(--text-dim)' }}>Trivy CVEs:</span>
                          <span style={{ color: lab.vulnerability_scan_result.summary.critical > 0 ? '#ef4444' : '#10b981', fontWeight: 600 }}>
                            {lab.vulnerability_scan_result.summary.critical} Crit / {lab.vulnerability_scan_result.summary.high} High ({lab.vulnerability_scan_result.total_findings || 0} total)
                          </span>
                        </div>
                      )}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ color: 'var(--text-dim)' }}>Running Sandboxes:</span>
                        <span style={{ color: activeCount > 0 ? '#10b981' : 'var(--text-muted)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {activeCount > 0 && <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', display: 'inline-block' }} />}
                          {activeCount} active sandbox{activeCount === 1 ? '' : 'es'}
                        </span>
                      </div>
                    </div>

                    {/* Expandable Active Sandboxes Drawer */}
                    {isExpanded && (
                      <div style={{ background: 'rgba(0, 0, 0, 0.35)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', padding: '12px', marginBottom: '16px' }}>
                        <div style={{ fontSize: '0.8rem', fontWeight: 600, marginBottom: '8px', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between' }}>
                          <span>Sandboxes for this Lab ({lab.active_sessions?.length || 0}):</span>
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Multiple sandboxes supported</span>
                        </div>

                        {(!lab.active_sessions || lab.active_sessions.length === 0) ? (
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', textAlign: 'center', padding: '10px' }}>
                            No running sandboxes for this lab yet. Click "Launch New Sandbox Instance" below to create one!
                          </div>
                        ) : (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            {lab.active_sessions.map(s => {
                              const isCurrent = s.session_id === activeSessionId;
                              const isDestroying = destroyingSessionId === s.session_id;

                              return (
                                <div
                                  key={s.session_id}
                                  style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    background: isCurrent ? 'rgba(6, 182, 212, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                                    border: `1px solid ${isCurrent ? '#06b6d4' : 'rgba(255, 255, 255, 0.06)'}`,
                                    padding: '8px 12px',
                                    borderRadius: 'var(--radius-sm)'
                                  }}
                                >
                                  <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                      <code style={{ fontSize: '0.82rem', fontWeight: 700, color: '#38bdf8' }}>{s.session_id}</code>
                                      {isCurrent && (
                                        <span className="badge badge-soc" style={{ fontSize: '0.65rem', padding: '2px 6px' }}>
                                          ACTIVE TARGET
                                        </span>
                                      )}
                                    </div>
                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                                      ns: {s.namespace} · mode: {s.isolation?.execution_mode || 'simulated'}
                                    </div>
                                  </div>

                                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                                    {!isCurrent && (
                                      <button
                                        className="btn btn-secondary"
                                        style={{ padding: '4px 8px', fontSize: '0.72rem', color: '#38bdf8' }}
                                        onClick={() => {
                                          if (onSelectSession) onSelectSession(s.session_id);
                                          showNotice(`Target switched to sandbox '${s.session_id}'`, 'info');
                                        }}
                                        title="Select this sandbox as active target across your dashboard"
                                      >
                                        Target
                                      </button>
                                    )}

                                    {/* Quick Navigation to User's Department */}
                                    {user?.role === 'red' && onNavigateRole && (
                                      <button
                                        className="btn btn-secondary"
                                        style={{ padding: '4px 8px', fontSize: '0.72rem', color: '#ef4444' }}
                                        onClick={() => {
                                          if (onSelectSession) onSelectSession(s.session_id);
                                          onNavigateRole('red');
                                        }}
                                        title="Open Red Team Console with this sandbox"
                                      >
                                        Red
                                      </button>
                                    )}
                                    {user?.role === 'blue' && onNavigateRole && (
                                      <button
                                        className="btn btn-secondary"
                                        style={{ padding: '4px 8px', fontSize: '0.72rem', color: '#06b6d4' }}
                                        onClick={() => {
                                          if (onSelectSession) onSelectSession(s.session_id);
                                          onNavigateRole('blue');
                                        }}
                                        title="Open Blue Team Hub with this sandbox"
                                      >
                                        Blue
                                      </button>
                                    )}
                                    {user?.role === 'soc' && onNavigateRole && (
                                      <button
                                        className="btn btn-secondary"
                                        style={{ padding: '4px 8px', fontSize: '0.72rem', color: '#10b981' }}
                                        onClick={() => {
                                          if (onSelectSession) onSelectSession(s.session_id);
                                          onNavigateRole('soc');
                                        }}
                                        title="Open SOC Desk with this sandbox"
                                      >
                                        SOC
                                      </button>
                                    )}
                                    {isAdmin && onNavigateRole && (
                                      <button
                                        className="btn btn-secondary"
                                        style={{ padding: '4px 8px', fontSize: '0.72rem', color: '#c084fc' }}
                                        onClick={() => {
                                          if (onSelectSession) onSelectSession(s.session_id);
                                          onNavigateRole('admin');
                                        }}
                                        title="View sandbox in Admin overview"
                                      >
                                        Admin
                                      </button>
                                    )}

                                    {/* Teardown Sandbox Button */}
                                    <button
                                      className="btn btn-secondary"
                                      style={{ padding: '4px 6px', fontSize: '0.72rem', color: '#ef4444' }}
                                      onClick={(e) => handleDestroySandbox(s.session_id, e)}
                                      disabled={isDestroying}
                                      title="Destroy and terminate this sandbox instance"
                                    >
                                      {isDestroying ? '...' : 'Delete'}
                                    </button>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Actions Bar */}
                  <div style={{ display: 'flex', gap: '8px', marginTop: '12px', borderTop: '1px solid var(--border-subtle)', paddingTop: '14px', flexWrap: 'wrap' }}>
                    {/* Build Image Artifact Button - for Admins when not yet built */}
                    {isAdmin && (!lab.image_digest || lab.build_status !== 'built') && (
                      <button
                        className="btn btn-secondary"
                        style={{ fontSize: '0.84rem', padding: '8px 12px', color: '#38bdf8', borderColor: 'rgba(56, 189, 248, 0.4)' }}
                        onClick={(e) => handleBuildLab(lab.id, e)}
                        disabled={buildingLabId === lab.id || lab.status === 'failed'}
                        title="Build a real container image from this lab's Dockerfile & context"
                      >
                        {buildingLabId === lab.id ? "Building Image..." : "Build Image"}
                      </button>
                    )}

                    {/* Launch Sandbox Instance */}
                    <button
                      className="btn btn-primary"
                      style={{ flex: 1, fontSize: '0.84rem', padding: '8px 12px' }}
                      onClick={() => handleLaunchSession(lab.id, lab.name)}
                      disabled={launchingLabId === lab.id || lab.status === 'failed' || (!lab.image_digest && !lab.image_tag)}
                      title={(!lab.image_digest && !lab.image_tag) ? "Build the image artifact first before launching" : "Launch a new isolated sandbox"}
                    >
                      {launchingLabId === lab.id ? "Spawning Sandbox..." : (!lab.image_digest && !lab.image_tag) ? "Build Required To Launch" : "Launch Sandbox"}
                    </button>

                    {/* Manage Sandboxes Drawer Toggle */}
                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: '0.84rem', padding: '8px 12px' }}
                      onClick={() => setExpandedLabId(isExpanded ? null : lab.id)}
                      title="View, target, and manage running sandbox instances"
                    >
                      {isExpanded ? "Hide" : `Sandboxes (${activeCount})`}
                    </button>

                    {/* Admin Only Archive Button */}
                    {isAdmin && (
                      <button
                        className="btn btn-secondary"
                        style={{ fontSize: '0.84rem', padding: '8px 10px', color: '#ef4444' }}
                        onClick={() => handleArchiveLab(lab.id)}
                        title="Archive this Lab (Admin only)"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

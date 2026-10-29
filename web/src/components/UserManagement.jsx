import React, { useEffect, useState } from 'react';

const ROLE_OPTIONS = [
  { value: 'red', label: 'Red Team' },
  { value: 'blue', label: 'Blue Team' },
  { value: 'soc', label: 'SOC Analyst' },
  { value: 'admin', label: 'Administrator' },
];

export default function UserManagement({ currentUser }) {
  const [users, setUsers] = useState([]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('red');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function requestJson(url, options = {}) {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Request failed (HTTP ${response.status})`);
    return data;
  }

  async function loadUsers() {
    setError('');
    setLoading(true);
    try {
      const data = await requestJson('/api/v1/auth/users');
      setUsers(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadUsers(); }, []);

  async function createUser(event) {
    event.preventDefault();
    setError('');
    setNotice('');
    setBusy(true);
    try {
      await requestJson('/api/v1/auth/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password, role }),
      });
      setUsername('');
      setPassword('');
      setNotice(`Created ${roleLabel(role)} account successfully.`);
      await loadUsers();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function updateUser(user, patch) {
    setError('');
    setNotice('');
    try {
      await requestJson(`/api/v1/auth/users/${encodeURIComponent(user.id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      setNotice(`Updated ${user.username}.`);
      await loadUsers();
    } catch (err) {
      setError(err.message);
    }
  }

  async function deleteUser(user) {
    if (!window.confirm(`Are you sure you want to permanently delete user "${user.username}"? This cannot be undone.`)) return;
    setError('');
    setNotice('');
    try {
      await requestJson(`/api/v1/auth/users/${encodeURIComponent(user.id)}`, {
        method: 'DELETE',
      });
      setNotice(`User "${user.username}" deleted successfully.`);
      await loadUsers();
    } catch (err) {
      setError(err.message);
    }
  }

  function roleLabel(value) {
    return ROLE_OPTIONS.find(option => option.value === value)?.label || value;
  }

  if (currentUser?.role !== 'admin') {
    return <section className="glass-panel users-access-denied"><h2>Administrator access required</h2><p>Only administrators can manage accounts.</p></section>;
  }

  return (
    <div className="users-page">
      <div className="users-page-header">
        <div>
          <div className="users-eyebrow">ACCESS CONTROL</div>
          <h1>User Management</h1>
          <p>Create accounts and assign a platform role. New accounts are scoped to your tenant.</p>
        </div>
        <div className="users-count"><strong>{users.length}</strong><span>active directory entries</span></div>
      </div>

      <section className="glass-panel users-create-panel">
        <div className="users-section-heading"><div><span className="users-section-kicker">NEW ACCOUNT</span><h2>Create a user</h2></div><span className="users-lock">ADMIN ONLY</span></div>
        <form className="users-create-form" onSubmit={createUser}>
          <div className="users-field"><label htmlFor="new-username">Username</label><input id="new-username" value={username} onChange={e => setUsername(e.target.value)} minLength={3} maxLength={80} pattern="[A-Za-z0-9._-]+" required placeholder="e.g. red.operator" autoComplete="off" /></div>
          <div className="users-field"><label htmlFor="new-password">Temporary password</label><input id="new-password" type="password" value={password} onChange={e => setPassword(e.target.value)} minLength={6} required autoComplete="new-password" placeholder="At least 6 characters" /></div>
          <div className="users-field"><label htmlFor="new-role">Platform role</label><select id="new-role" value={role} onChange={e => setRole(e.target.value)}>{ROLE_OPTIONS.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}</select></div>
          <button className="btn btn-primary users-create-button" disabled={busy}>{busy ? 'Creating…' : '+ Create user'}</button>
        </form>
        <p className="users-help">Passwords are stored as salted PBKDF2 hashes (minimum 6 characters). Usernames are unique across the installation.</p>
      </section>

      {error && <div className="users-message users-message-error" role="alert">{error}</div>}
      {notice && <div className="users-message users-message-success" role="status">{notice}</div>}

      <section className="glass-panel users-directory-panel">
        <div className="users-section-heading"><div><span className="users-section-kicker">TENANT DIRECTORY</span><h2>Accounts and permissions</h2></div><button className="btn btn-outline" onClick={loadUsers} disabled={loading}>↻ Refresh</button></div>
        {loading ? <div className="users-empty">Loading users…</div> : users.length === 0 ? <div className="users-empty">No credential-backed accounts were found. Create the first user above.</div> : (
          <div className="users-table-wrap"><table className="users-table"><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Created</th><th>Access</th><th>Actions</th></tr></thead>
            <tbody>{users.map(user => <tr key={user.id}>
              <td><div className="users-person"><span className={`users-avatar role-${user.role}`}>{user.username.slice(0, 1).toUpperCase()}</span><div><strong>{user.username}</strong><small>{user.id === currentUser?.id ? 'Your account' : user.id}</small></div></div></td>
              <td><select aria-label={`Role for ${user.username}`} className="users-role-select" value={user.role} disabled={user.id === currentUser?.id} onChange={e => updateUser(user, { role: e.target.value })}>{ROLE_OPTIONS.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}</select></td>
              <td><span className={`users-status ${user.is_active ? 'is-active' : 'is-inactive'}`}><span />{user.is_active ? 'Active' : 'Disabled'}</span></td>
              <td>{user.created_at ? new Date(user.created_at).toLocaleDateString() : '—'}</td>
              <td><button className={`users-toggle ${user.is_active ? 'disable' : 'enable'}`} disabled={user.id === currentUser?.id} onClick={() => updateUser(user, { is_active: !user.is_active })}>{user.is_active ? 'Disable' : 'Enable'}</button></td>
              <td>
                <button
                  className="btn btn-secondary"
                  style={{
                    padding: '4px 10px',
                    fontSize: '0.78rem',
                    color: user.id === currentUser?.id ? 'var(--text-dim)' : '#ef4444',
                    borderColor: user.id === currentUser?.id ? 'transparent' : 'rgba(239, 68, 68, 0.3)',
                    background: 'rgba(0, 0, 0, 0.3)',
                    cursor: user.id === currentUser?.id ? 'not-allowed' : 'pointer'
                  }}
                  disabled={user.id === currentUser?.id}
                  onClick={() => deleteUser(user)}
                  title={user.id === currentUser?.id ? "You cannot delete your own account" : `Permanently delete ${user.username}`}
                >
                  Delete
                </button>
              </td>
            </tr>)}</tbody>
          </table></div>
        )}
      </section>
    </div>
  );
}

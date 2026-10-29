import React, { useState, useEffect, useRef } from 'react';

export default function CopilotDrawer({ isOpen, onClose, currentRole, activeSessionId, initialPrompt }) {
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: `Hello! I am your AI Security Copilot (${currentRole.toUpperCase()} perspective).\nHow can I assist your security validation workflow today?`
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    if (initialPrompt) {
      handleSendPrompt(initialPrompt);
    }
  }, [initialPrompt]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSendPrompt = async (textToSend) => {
    const prompt = textToSend || inputText;
    if (!prompt.trim()) return;

    setMessages(prev => [...prev, { sender: 'user', text: prompt }]);
    if (!textToSend) setInputText('');
    setLoading(true);

    try {
      const res = await fetch('/api/v1/copilot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: prompt,
          session_id: activeSessionId
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail?.message || data.detail || `HTTP ${res.status}`);
      setMessages(prev => [...prev, { sender: 'ai', text: `${data.reply}\n\n[Response source: ${data.provider_mode || 'unknown'}]` }]);
    } catch (err) {
      setMessages(prev => [...prev, { sender: 'ai', text: `Error contacting copilot: ${err.message}` }]);
    } finally {
      setLoading(false);
    }
  };

  const handleQuickAction = (actionType) => {
    if (actionType === 'explain') {
      handleSendPrompt("Explain the most recent critical security alert, including MITRE tactics and remediation.");
    } else if (actionType === 'sigma') {
      handleSendPrompt("Draft a Sigma detection rule for MITRE technique T1210 (Exploitation of Remote Services).");
    } else if (actionType === 'attack') {
      handleSendPrompt("Given the open ports 80 and 445 discovered in recon, suggest the next plausible MITRE attack step.");
    } else if (actionType === 'summary') {
      handleSendPrompt("Provide an executive incident summary for this session's security test.");
    }
  };

  return (
    <div className={`copilot-drawer ${isOpen ? '' : 'closed'}`} id="copilot-drawer">
      {/* Header */}
      <div className="copilot-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '28px',
            height: '28px',
            borderRadius: 'var(--radius-full)',
            background: 'var(--accent)',
            color: '#fff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '0.85rem'
          }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.92rem' }}>AI Security Copilot</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              Persona: <strong style={{ color: '#38bdf8' }}>{currentRole.toUpperCase()}</strong> · context-assisted; local fallback is deterministic
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '1.1rem' }}
        >
          ✕
        </button>
      </div>

      {/* Quick Action Chips */}
      <div style={{ display: 'flex', gap: '6px', padding: '10px 16px', background: 'rgba(0,0,0,0.2)', overflowX: 'auto' }}>
        <button
          className="badge badge-untested"
          style={{ cursor: 'pointer', whiteSpace: 'nowrap' }}
          onClick={() => handleQuickAction('explain')}
        >
          Explain Alert
        </button>
        <button
          className="badge badge-untested"
          style={{ cursor: 'pointer', whiteSpace: 'nowrap' }}
          onClick={() => handleQuickAction('sigma')}
        >
          Draft Sigma Rule
        </button>
        <button
          className="badge badge-untested"
          style={{ cursor: 'pointer', whiteSpace: 'nowrap' }}
          onClick={() => handleQuickAction('attack')}
        >
          Suggest Attack
        </button>
        <button
          className="badge badge-untested"
          style={{ cursor: 'pointer', whiteSpace: 'nowrap' }}
          onClick={() => handleQuickAction('summary')}
        >
          Summarize
        </button>
      </div>

      {/* Message Stream */}
      <div className="copilot-messages">
        {messages.map((m, i) => (
          <div
            key={i}
            className={`message-bubble ${m.sender === 'user' ? 'message-user' : 'message-ai'}`}
            style={{ whiteSpace: 'pre-wrap' }}
          >
            {m.text}
          </div>
        ))}
        {loading && (
          <div className="message-bubble message-ai" style={{ color: 'var(--text-dim)', fontStyle: 'italic' }}>
            Analyzing session telemetry & compiling response...
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendPrompt();
        }}
        style={{
          display: 'flex',
          padding: '12px 16px',
          borderTop: '1px solid var(--border-subtle)',
          gap: '10px',
          background: '#090d16'
        }}
      >
        <input
          id="input-copilot-chat"
          type="text"
          placeholder="Ask copilot about alerts, rules, or MITRE..."
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          style={{
            flex: 1,
            background: '#05070c',
            border: '1px solid #1e293b',
            borderRadius: 'var(--radius-md)',
            padding: '8px 14px',
            color: '#ffffff',
            fontSize: '0.84rem',
            outline: 'none'
          }}
        />
        <button
          id="btn-copilot-send"
          type="submit"
          className="btn btn-primary"
          style={{ padding: '8px 14px', fontSize: '0.82rem' }}
          disabled={loading}
        >
          Send
        </button>
      </form>
    </div>
  );
}

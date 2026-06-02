import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  ClerkProvider,
  SignInButton,
  SignedIn,
  SignedOut,
  UserButton,
  useAuth,
  useClerk,
  useUser
} from '@clerk/clerk-react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  FileArchive,
  Github,
  LogOut,
  Download,
  MessageCircle,
  RefreshCw,
  Shield,
  Upload,
  XCircle
} from 'lucide-react';
import './styles.css';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000';
const CLERK_PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY;

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

function formatDate(value) {
  if (!value) return 'Not started';
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short'
  }).format(new Date(value));
}

function normalizeScan(scan) {
  return {
    ...scan,
    vulnerabilityCount: scan.vulnerability_count ?? scan.vulnerabilities?.length ?? 0,
    progress: scan.progress ?? 0,
    organizationId: scan.organization_id ?? scan.organizationId ?? null,
    teamId: scan.team_id ?? scan.teamId ?? null,
    securityScore: scan.security_score
  };
}

function getSeverityCounts(vulnerabilities) {
  return vulnerabilities.reduce(
    (acc, item) => {
      const severity = String(item.severity || 'info').toLowerCase();
      if (!acc[severity]) {
        acc[severity] = 0;
      }
      acc[severity] += 1;
      return acc;
    },
    {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    }
  );
}

function SeverityChart({ counts }) {
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);

  if (total === 0) {
    return <div className="severity-chart empty-state">No severity findings to display.</div>;
  }

  return (
    <div className="severity-chart">
      <div className="severity-chart-header">
        <span>Severity distribution</span>
        <strong>{total} findings</strong>
      </div>
      {severityOrder.map((severity) => {
        const count = counts[severity] || 0;
        const width = total ? `${(count / total) * 100}%` : '0%';

        return (
          <div key={severity} className="severity-chart-row">
            <span className={`severity-chart-label severity-${severity}`}>{severity}</span>
            <div className="severity-chart-track">
              <div className="severity-chart-fill" style={{ width }} />
            </div>
            <span className="severity-chart-count">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

async function getAuthHeaders(getToken) {
  const token = await getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function apiGet(path, getToken) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: await getAuthHeaders(getToken)
  });
  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}`);
  }
  return response.json();
}

async function uploadZip(file, getToken) {
  const formData = new FormData();
  formData.append('repository', file);

  const response = await fetch(`${API_BASE_URL}/api/scans/zip`, {
    method: 'POST',
    headers: await getAuthHeaders(getToken),
    body: formData
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.error?.message || `Upload failed with status ${response.status}`);
  }

  return response.json();
}

async function submitGithubRepository(repositoryUrl, getToken) {
  const response = await fetch(`${API_BASE_URL}/api/scans/github`, {
    method: 'POST',
    headers: {
      ...(await getAuthHeaders(getToken)),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ repositoryUrl })
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.error?.message || `GitHub scan failed with status ${response.status}`);
  }

  return response.json();
}

async function apiPatch(path, body, getToken) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'PATCH',
    headers: {
      ...(await getAuthHeaders(getToken)),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error?.message || `Request failed with status ${response.status}`);
  }

  return response.json();
}

async function downloadScanPdf(scan, getToken) {
  const response = await fetch(`${API_BASE_URL}/api/scans/${scan.id}/export.pdf`, {
    headers: await getAuthHeaders(getToken)
  });

  if (!response.ok) {
    throw new Error(`PDF export failed with status ${response.status}`);
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${scan.project_name}-security-report.pdf`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
}

async function loadSettings(getToken) {
  const response = await fetch(`${API_BASE_URL}/api/settings`, {
    headers: await getAuthHeaders(getToken)
  });

  if (!response.ok) {
    throw new Error(`Settings request failed with status ${response.status}`);
  }

  return response.json();
}

async function saveSettings(payload, getToken) {
  const response = await fetch(`${API_BASE_URL}/api/settings`, {
    method: 'PATCH',
    headers: {
      ...(await getAuthHeaders(getToken)),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.error?.message || `Settings update failed with status ${response.status}`);
  }

  return response.json();
}

async function sendChatQuestion(questionPayload, getToken) {
  const response = await fetch(`${API_BASE_URL}/api/scans/chat`, {
    method: 'POST',
    headers: {
      ...(await getAuthHeaders(getToken)),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(questionPayload)
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.error?.message || `Chat request failed with status ${response.status}`);
  }

  return response.json();
}

function StatusBadge({ status }) {
  const statusConfig = {
    queued: { icon: Clock3, label: 'Queued' },
    running: { icon: RefreshCw, label: 'Running' },
    completed: { icon: CheckCircle2, label: 'Completed' },
    failed: { icon: XCircle, label: 'Failed' }
  };

  const config = statusConfig[status] || statusConfig.queued;
  const Icon = config.icon;

  return (
    <span className={`status-badge status-${status}`}>
      <Icon size={14} />
      {config.label}
    </span>
  );
}

function ProgressBar({ value }) {
  const progress = Math.max(0, Math.min(100, value ?? 0));

  return (
    <div className="progress-bar" aria-label={`Scan progress ${progress} percent`}>
      <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
      <span className="progress-bar-text">{progress}%</span>
    </div>
  );
}

function ScoreRing({ score }) {
  const displayScore = typeof score === 'number' ? score : 0;
  const angle = Math.max(0, Math.min(100, displayScore)) * 3.6;

  return (
    <div
      className="score-ring"
      style={{
        background: `conic-gradient(var(--score-color) ${angle}deg, var(--border) ${angle}deg)`
      }}
      aria-label={`Security score ${displayScore} out of 100`}
    >
      <div className="score-ring-inner">
        <strong>{typeof score === 'number' ? score : '-'}</strong>
        <span>/100</span>
      </div>
    </div>
  );
}

function UploadPanel({ onScanCreated, busy, setBusy, setNotice, getToken, currentUser }) {
  const [file, setFile] = useState(null);
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [organizationId, setOrganizationId] = useState('');
  const [teamId, setTeamId] = useState('');

  async function handleZipSubmit(event) {
    event.preventDefault();
    if (!file) {
      setNotice({ type: 'error', message: 'Choose a ZIP repository first.' });
      return;
    }

    setBusy(true);
    try {
      const form = new FormData();
      form.append('repository', file);
      if (organizationId) form.append('organizationId', organizationId);
      if (teamId) form.append('teamId', teamId);

      const response = await fetch(`${API_BASE_URL}/api/scans/zip`, {
        method: 'POST',
        headers: await getAuthHeaders(getToken),
        body: form
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(body?.error?.message || `Upload failed with status ${response.status}`);
      }

      const result = await response.json();
      setNotice({ type: 'success', message: 'ZIP scan queued.' });
      onScanCreated(result.scan.id);
      setFile(null);
      event.target.reset();
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    } finally {
      setBusy(false);
    }
  }

  async function handleGithubSubmit(event) {
    event.preventDefault();
    if (!repositoryUrl.trim()) {
      setNotice({ type: 'error', message: 'Paste a GitHub repository URL first.' });
      return;
    }

    setBusy(true);
    try {
      const payload = { repositoryUrl: repositoryUrl.trim() };
      if (organizationId) payload.organizationId = organizationId;
      if (teamId) payload.teamId = teamId;

      const response = await fetch(`${API_BASE_URL}/api/scans/github`, {
        method: 'POST',
        headers: {
          ...(await getAuthHeaders(getToken)),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(body?.error?.message || `GitHub scan failed with status ${response.status}`);
      }

      const result = await response.json();
      setNotice({ type: 'success', message: 'GitHub scan queued.' });
      onScanCreated(result.scan.id);
      setRepositoryUrl('');
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel upload-panel">
      <div className="panel-heading">
        <Shield size={22} />
        <div>
          <h1>AI Code Security Reviewer</h1>
          <p>{currentUser.email} · {currentUser.role === 'admin' ? 'Admin' : 'User'}</p>
        </div>
      </div>

      <form className="upload-box" onSubmit={handleZipSubmit}>
        <div className="upload-title">
          <FileArchive size={18} />
          <h2>ZIP Upload</h2>
        </div>
        <label className="file-drop">
          <Upload size={22} />
          <span>{file ? file.name : 'Choose repository ZIP'}</span>
          <input
            type="file"
            accept=".zip"
            onChange={(event) => setFile(event.target.files?.[0] || null)}
          />
        </label>
        <input
          type="text"
          placeholder="Organization ID (optional)"
          value={organizationId}
          onChange={(e) => setOrganizationId(e.target.value)}
        />
        <input
          type="text"
          placeholder="Team ID (optional)"
          value={teamId}
          onChange={(e) => setTeamId(e.target.value)}
        />
        <button type="submit" disabled={busy}>
          <Upload size={16} />
          Queue ZIP Scan
        </button>
      </form>

      <form className="upload-box" onSubmit={handleGithubSubmit}>
        <div className="upload-title">
          <Github size={18} />
          <h2>GitHub Repository</h2>
        </div>
        <input
          type="url"
          placeholder="https://github.com/org/repository"
          value={repositoryUrl}
          onChange={(event) => setRepositoryUrl(event.target.value)}
        />
        <input
          type="text"
          placeholder="Organization ID (optional)"
          value={organizationId}
          onChange={(e) => setOrganizationId(e.target.value)}
        />
        <input
          type="text"
          placeholder="Team ID (optional)"
          value={teamId}
          onChange={(e) => setTeamId(e.target.value)}
        />
        <button type="submit" disabled={busy}>
          <Github size={16} />
          Queue GitHub Scan
        </button>
      </form>
    </section>
  );
}

function ScanHistory({ scans, selectedScanId, onSelectScan, onRefresh, loading, isAdmin }) {
  return (
    <section className="panel history-panel">
      <div className="section-header">
        <div>
          <h2>{isAdmin ? 'All Scan History' : 'Your Scan History'}</h2>
          <p>
            {isAdmin
              ? `${scans.length} recent platform scans`
              : `${scans.length} scans submitted by your account`}
          </p>
        </div>
        <button className="icon-button" onClick={onRefresh} disabled={loading} title="Refresh scans">
          <RefreshCw size={18} />
        </button>
      </div>

      <div className="scan-list">
        {scans.map((scan) => (
          <button
            key={scan.id}
            className={`scan-row ${selectedScanId === scan.id ? 'selected' : ''}`}
            onClick={() => onSelectScan(scan.id)}
          >
            <div>
              <strong>{scan.project_name}</strong>
              <span>{formatDate(scan.created_at)}</span>
              {(scan.organizationId || scan.teamId) && (
                <span className="muted">
                  {scan.organizationId ? `Org: ${scan.organizationId}` : ''}
                  {scan.organizationId && scan.teamId ? ' · ' : ''}
                  {scan.teamId ? `Team: ${scan.teamId}` : ''}
                </span>
              )}
            </div>
            <div className="scan-row-meta">
              <StatusBadge status={scan.status} />
              <span>{scan.vulnerabilityCount} findings</span>
              <ProgressBar value={scan.progress} />
            </div>
          </button>
        ))}
        {scans.length === 0 && (
          <div className="empty-state">
            {isAdmin ? 'No platform scans yet.' : 'No scans yet for your account.'}
          </div>
        )}
      </div>
    </section>
  );
}

function VulnerabilityTable({ vulnerabilities }) {
  const sorted = useMemo(() => {
    return [...vulnerabilities].sort((left, right) => {
      return severityOrder.indexOf(left.severity) - severityOrder.indexOf(right.severity);
    });
  }, [vulnerabilities]);

  if (sorted.length === 0) {
    return <div className="empty-state">No vulnerabilities recorded for this scan.</div>;
  }

  return (
    <div className="vulnerability-list">
      {sorted.map((finding) => (
        <article key={finding.id} className={`finding severity-${finding.severity}`}>
          <div className="finding-topline">
            <span className="severity-pill">{finding.severity}</span>
            <strong>{finding.title}</strong>
          </div>
          <div className="finding-location">
            {finding.file_path}
            {finding.line_start ? `:${finding.line_start}` : ''}
          </div>
          <p>{finding.description}</p>
          <div className="recommendation">
            <span>Fix</span>
            <p>{finding.recommendation}</p>
          </div>
          {finding.evidence && <pre>{finding.evidence}</pre>}
        </article>
      ))}
    </div>
  );
}

function ReportPanel({ scan, loading, getToken, setNotice, onExported }) {
  if (loading && !scan) {
    return (
      <section className="panel report-panel">
        <div className="empty-state">Loading report...</div>
      </section>
    );
  }

  if (!scan) {
    return (
      <section className="panel report-panel">
        <div className="empty-state">Select or queue a scan to view its report.</div>
      </section>
    );
  }

  const vulnerabilities = scan.vulnerabilities || [];

  return (
    <section className="panel report-panel">
      <div className="report-header">
        <div>
          <div className="report-kicker">Security Report</div>
          <h2>{scan.project_name}</h2>
          <div className="report-meta">
            <StatusBadge status={scan.status} />
            <span>{scan.source_type}</span>
            {scan.user_email && <span>{scan.user_email}</span>}
            <span>{formatDate(scan.created_at)}</span>
            {scan.organizationId && <span>{`Org: ${scan.organizationId}`}</span>}
            {scan.teamId && <span>{`Team: ${scan.teamId}`}</span>}
            <ProgressBar value={scan.progress} />
          </div>
        </div>
        <div className="report-actions">
          <button
            className="secondary-action"
            onClick={async () => {
              try {
                await downloadScanPdf(scan, getToken);
                setNotice({ type: 'success', message: 'PDF report exported.' });
                onExported();
              } catch (error) {
                setNotice({ type: 'error', message: error.message });
              }
            }}
          >
            <Download size={16} />
            Export PDF
          </button>
          <ScoreRing score={scan.security_score} />
        </div>
      </div>

      {scan.error_message && (
        <div className="notice error">
          <AlertTriangle size={16} />
          {scan.error_message}
        </div>
      )}

      <div className="summary-grid">
        <div>
          <span>Total findings</span>
          <strong>{vulnerabilities.length}</strong>
        </div>
        <div>
          <span>High or critical</span>
          <strong>
            {vulnerabilities.filter((item) => ['critical', 'high'].includes(item.severity)).length}
          </strong>
        </div>
        <div>
          <span>Completed</span>
          <strong>{scan.completed_at ? formatDate(scan.completed_at) : '-'}</strong>
        </div>
      </div>

      <SeverityChart counts={getSeverityCounts(vulnerabilities)} />

      <VulnerabilityTable vulnerabilities={vulnerabilities} />
    </section>
  );
}

function ConversationHistorySidebar({ chatMessages, selectedMessageId, onSelectMessage, onNewChat }) {
  return (
    <aside className="chat-sidebar panel chat-sidebar-dark">
      <div className="sidebar-top">
        <div className="sidebar-brand">
          <MessageCircle size={20} />
          <div>
            <strong>Security Chat</strong>
            <span>AI assistant</span>
          </div>
        </div>
        <button type="button" className="new-chat-button" onClick={onNewChat}>
          + New chat
        </button>
      </div>
      <div className="sidebar-list">
        {chatMessages.length === 0 ? (
          <div className="empty-state">No history yet. Ask a question to start the chat.</div>
        ) : (
          chatMessages.map((message) => (
            <button
              key={message.id}
              type="button"
              className={`sidebar-item ${selectedMessageId === message.id ? 'selected' : ''}`}
              onClick={() => onSelectMessage(message.id)}
            >
              <span className="sidebar-role">{message.role === 'assistant' ? 'AI' : 'You'}</span>
              <span className="sidebar-snippet">{message.text.slice(0, 80)}{message.text.length > 80 ? '…' : ''}</span>
              <span className="sidebar-time">{formatDate(message.createdAt)}</span>
            </button>
          ))
        )}
      </div>
    </aside>
  );
}

function ChatPanel({ selectedScan, chatMessages, draft, setDraft, onSend, onClear, chatBusy }) {
  const chatEndRef = useRef(null);
  const selectedCount = selectedScan ? selectedScan.vulnerability_count ?? selectedScan.vulnerabilities?.length ?? 0 : 0;
  const isSendDisabled = chatBusy || !draft.trim() || !selectedScan;

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [chatMessages, chatBusy]);

  return (
    <section className="panel chat-panel">
      <div className="chat-header">
        <div>
          <h2>Chat with Security AI</h2>
          <p>Ask questions about the selected scan and receive context-aware guidance.</p>
        </div>
        <div className="chat-header-info">
          <span>{selectedScan ? selectedScan.project_name : 'No scan selected'}</span>
          <span>{selectedScan ? `${selectedCount} findings` : 'Select a scan to get started'}</span>
        </div>
      </div>

      <div className="chat-thread" role="log" aria-live="polite" aria-label="Chat conversation">
        {chatMessages.map((message) => (
          <article key={message.id} className={`chat-message chat-${message.role}`}>
            <div className="chat-message-bubble">
              <div className="chat-message-header">
                <span className="chat-role">{message.role === 'assistant' ? 'Security AI' : 'You'}</span>
                <span className="chat-time">{formatDate(message.createdAt)}</span>
              </div>
              <p>{message.text}</p>
            </div>
          </article>
        ))}
        {chatBusy && (
          <article className="chat-message chat-assistant typing-placeholder">
            <div className="chat-message-bubble">
              <div className="chat-message-header">
                <span className="chat-role">Security AI</span>
              </div>
              <p>Thinking through your scan context…</p>
            </div>
          </article>
        )}
        <div ref={chatEndRef} />
      </div>

      <form
        className="chat-entry"
        onSubmit={(event) => {
          event.preventDefault();
          onSend();
        }}
      >
        <textarea
          value={draft}
          placeholder={selectedScan ? 'Ask a question about this scan or write a note...' : 'Select a scan first to use the chat.'}
          onChange={(event) => setDraft(event.target.value)}
          disabled={chatBusy || !selectedScan}
        />
        <div className="chat-actions">
          <button type="submit" className="primary-action" disabled={isSendDisabled}>
            {chatBusy ? 'Thinking…' : 'Send'}
          </button>
          <button type="button" className="secondary-action" onClick={onClear} disabled={chatBusy || chatMessages.length === 0}>
            Clear chat
          </button>
        </div>
      </form>
    </section>
  );
}

function SettingsPanel({ currentUser, settings, busy, onSave, setSettings }) {
  if (!settings) {
    return (
      <section className="panel settings-panel">
        <div className="empty-state">Loading settings...</div>
      </section>
    );
  }

  return (
    <section className="panel settings-panel">
      <div className="section-header">
        <div>
          <h2>Settings & Profile</h2>
          <p>Manage your profile view and the AI model configuration for scans.</p>
        </div>
      </div>

      <div className="profile-summary">
        <h3>Profile</h3>
        <div>
          <span>Email</span>
          <strong>{currentUser.email}</strong>
        </div>
        <div>
          <span>Role</span>
          <strong>{currentUser.role === 'admin' ? 'Administrator' : 'Standard user'}</strong>
        </div>
      </div>

      <div className="model-settings">
        <h3>Model integration</h3>
        <label>
          AI provider
          <select
            value={settings.aiProvider}
            onChange={(event) => setSettings({ ...settings, aiProvider: event.target.value })}
            disabled={busy || currentUser.role !== 'admin'}
          >
            <option value="openai">OpenAI</option>
            <option value="ollama">Ollama</option>
            <option value="groq">GroqCloud</option>
          </select>
        </label>
        <label>
          OpenAI model
          <input
            type="text"
            value={settings.openAiModel}
            onChange={(event) => setSettings({ ...settings, openAiModel: event.target.value })}
            disabled={busy || currentUser.role !== 'admin'}
          />
        </label>
        <label>
          Ollama base URL
          <input
            type="url"
            value={settings.ollamaBaseUrl}
            onChange={(event) => setSettings({ ...settings, ollamaBaseUrl: event.target.value })}
            disabled={busy || currentUser.role !== 'admin'}
          />
        </label>
        <label>
          Ollama model
          <input
            type="text"
            value={settings.ollamaModel}
            onChange={(event) => setSettings({ ...settings, ollamaModel: event.target.value })}
            disabled={busy || currentUser.role !== 'admin'}
          />
        </label>
        <label>
          GroqCloud model
          <input
            type="text"
            value={settings.groqModel}
            onChange={(event) => setSettings({ ...settings, groqModel: event.target.value })}
            disabled={busy || currentUser.role !== 'admin'}
          />
        </label>
        <label>
          AI analysis enabled
          <select
            value={String(settings.aiAnalysisEnabled)}
            onChange={(event) => setSettings({ ...settings, aiAnalysisEnabled: event.target.value === 'true' })}
            disabled={busy || currentUser.role !== 'admin'}
          >
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>
        </label>

        <div className="settings-note">
          Runtime settings are updated in memory. Backend environment variables still determine startup defaults.
        </div>

        {currentUser.role === 'admin' && (
          <button type="button" disabled={busy} onClick={onSave} className="secondary-action">
            Save model settings
          </button>
        )}
      </div>
    </section>
  );
}

function WelcomePanel({ currentUser, role, onNavigate }) {
  return (
    <section className="panel welcome-panel">
      <div className="welcome-card">
        <h1>Welcome back, {currentUser.email.split('@')[0] || currentUser.email}!</h1>
        <p>Start a new scan, review your history, or configure your AI model provider.</p>
        <div className="welcome-actions">
          <button onClick={() => onNavigate('dashboard')}>Open Dashboard</button>
          <button onClick={() => onNavigate('chat')}>Open Chat Notes</button>
          <button onClick={() => onNavigate('settings')}>Open Settings</button>
          {role === 'admin' && <button onClick={() => onNavigate('admin')}>Open Admin</button>}
        </div>
      </div>
    </section>
  );
}

function AdminPanel({ summary, isAdmin, loading }) {
  if (!isAdmin) {
    return null;
  }

  return (
    <section className="panel admin-panel">
      <div className="section-header">
        <div>
          <h2>Admin Dashboard</h2>
          <p>Platform-wide scan activity and user isolation checks</p>
        </div>
        {loading && <span className="muted">Refreshing...</span>}
      </div>
      <div className="admin-grid">
        <div>
          <span>Total scans</span>
          <strong>{summary?.total_scans ?? 0}</strong>
        </div>
        <div>
          <span>Completed</span>
          <strong>{summary?.completed_scans ?? 0}</strong>
        </div>
        <div>
          <span>Queued/running</span>
          <strong>{(summary?.queued_scans ?? 0) + (summary?.running_scans ?? 0)}</strong>
        </div>
        <div>
          <span>Users</span>
          <strong>{summary?.user_count ?? 0}</strong>
        </div>
        <div>
          <span>Average score</span>
          <strong>{summary?.average_security_score ?? 0}</strong>
        </div>
      </div>
    </section>
  );
}

function AuditLogPanel({ auditLogs, isAdmin, auditFilters, setAuditFilters }) {
  if (!isAdmin) {
    return null;
  }

  return (
    <section className="panel audit-panel">
      <div className="section-header">
        <div>
          <h2>Audit Log</h2>
          <p>Security-relevant actions across the platform</p>
        </div>
      </div>
      <div className="audit-filter-row">
        <label>
          Action
          <input
            type="text"
            placeholder="scan.started, user.role.updated"
            value={auditFilters.action}
            onChange={(event) => setAuditFilters((prev) => ({ ...prev, action: event.target.value }))}
          />
        </label>
        <label>
          Target type
          <input
            type="text"
            placeholder="scan, user"
            value={auditFilters.targetType}
            onChange={(event) => setAuditFilters((prev) => ({ ...prev, targetType: event.target.value }))}
          />
        </label>
        <label>
          Actor email
          <input
            type="text"
            placeholder="admin@example.com"
            value={auditFilters.actorEmail}
            onChange={(event) => setAuditFilters((prev) => ({ ...prev, actorEmail: event.target.value }))}
          />
        </label>
      </div>
      <div className="audit-list">
        {auditLogs.map((log) => (
          <article key={log.id} className="audit-row">
            <div>
              <strong>{log.action}</strong>
              <span>{log.actor_email || log.actor_user_id || 'system'}</span>
            </div>
            <div>
              <span>{log.target_type}</span>
              <span>{formatDate(log.created_at)}</span>
            </div>
          </article>
        ))}
        {auditLogs.length === 0 && <div className="empty-state">No audit events yet.</div>}
      </div>
    </section>
  );
}

function UsersManagementPanel({ users, isAdmin, getToken, setNotice, onChanged }) {
  if (!isAdmin) {
    return null;
  }

  async function changeRole(user, role) {
    try {
      await apiPatch(`/api/admin/users/${user.id}/role`, { role }, getToken);
      setNotice({ type: 'success', message: `${user.email || user.id} updated to ${role}.` });
      onChanged();
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    }
  }

  return (
    <section className="panel users-panel">
      <div className="section-header">
        <div>
          <h2>Users Management</h2>
          <p>Manage Clerk-backed roles for system access</p>
        </div>
      </div>
      <div className="users-list">
        {users.map((managedUser) => (
          <article key={managedUser.id} className="user-row">
            <div>
              <strong>{managedUser.email || managedUser.id}</strong>
              <span>{managedUser.firstName || managedUser.lastName ? `${managedUser.firstName || ''} ${managedUser.lastName || ''}`.trim() : managedUser.id}</span>
            </div>
            <div className="role-control">
              <span className={`role-pill role-${managedUser.role}`}>{managedUser.role}</span>
              <button disabled={managedUser.role === 'user'} onClick={() => changeRole(managedUser, 'user')}>
                User
              </button>
              <button disabled={managedUser.role === 'admin'} onClick={() => changeRole(managedUser, 'admin')}>
                Admin
              </button>
            </div>
          </article>
        ))}
        {users.length === 0 && <div className="empty-state">No Clerk users found.</div>}
      </div>
    </section>
  );
}

function AuthSetupNotice() {
  return (
    <main className="auth-shell">
      <section className="auth-card">
        <Shield size={34} />
        <h1>Clerk setup required</h1>
        <p>Add your Clerk publishable key to `frontend/.env`, then restart the frontend.</p>
        <pre>VITE_CLERK_PUBLISHABLE_KEY=pk_test_...</pre>
      </section>
    </main>
  );
}

function SignInScreen() {
  return (
    <main className="auth-shell">
      <section className="auth-card">
        <Shield size={38} />
        <h1>AI Code Security Reviewer</h1>
        <p>Sign in to upload repositories, view your scan history, and access role-based dashboards.</p>
        <SignInButton mode="modal">
          <button className="primary-auth-button">Sign in</button>
        </SignInButton>
      </section>
    </main>
  );
}

function DashboardApp() {
  const { getToken } = useAuth();
  const { signOut } = useClerk();
  const { user } = useUser();
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [selectedScan, setSelectedScan] = useState(null);
  const [adminSummary, setAdminSummary] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditFilters, setAuditFilters] = useState({ action: '', targetType: '', actorEmail: '' });
  const [managedUsers, setManagedUsers] = useState([]);
  const [settings, setSettings] = useState(null);
  const [settingsLoading, setSettingsLoading] = useState(false);
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [chatBusy, setChatBusy] = useState(false);
  const [chatStorageKey, setChatStorageKey] = useState('scanChatHistory:global');
  const [selectedChatHistoryId, setSelectedChatHistoryId] = useState(null);
  const [activeWorkspace, setActiveWorkspace] = useState('welcome');
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const role = user?.publicMetadata?.role === 'admin' ? 'admin' : 'user';
  const currentUser = {
    email: user?.primaryEmailAddress?.emailAddress || user?.username || 'Signed-in user',
    role
  };

  async function loadScans() {
    setLoading(true);
    try {
      const result = await apiGet('/api/scans', getToken);
      const normalizedScans = result.scans.map(normalizeScan);
      setScans(normalizedScans);

      const selectedStillVisible = normalizedScans.some((scan) => scan.id === selectedScanId);
      if (normalizedScans.length === 0) {
        setSelectedScanId(null);
        setSelectedScan(null);
      } else if (!selectedScanId || !selectedStillVisible) {
        setSelectedScanId(normalizedScans[0].id);
      }
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    } finally {
      setLoading(false);
    }
  }

  async function loadScan(scanId) {
    if (!scanId) return;
    setLoading(true);
    try {
      const result = await apiGet(`/api/scans/${scanId}`, getToken);
      setSelectedScan(result.scan);
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    } finally {
      setLoading(false);
    }
  }

  async function loadAdminSummary() {
    if (role !== 'admin') return;

    try {
      const result = await apiGet('/api/scans/admin/summary', getToken);
      setAdminSummary(result.summary);
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    }
  }

  async function loadAuditLogs() {
    if (role !== 'admin') return;

    try {
      const query = new URLSearchParams(
        Object.entries(auditFilters).reduce((acc, [key, value]) => {
          if (value?.trim()) acc[key] = value.trim();
          return acc;
        }, {})
      ).toString();
      const path = `/api/admin/audit-logs${query ? `?${query}` : ''}`;
      const result = await apiGet(path, getToken);
      setAuditLogs(result.auditLogs);
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    }
  }

  async function loadManagedUsers() {
    if (role !== 'admin') return;

    try {
      const result = await apiGet('/api/admin/users', getToken);
      setManagedUsers(result.users);
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    }
  }

  function handleScanCreated(scanId) {
    setSelectedScanId(scanId);
    loadScans();
    loadScan(scanId);
    loadAdminSummary();
    loadAuditLogs();
    loadManagedUsers();
  }

  async function loadAppSettings() {
    setSettingsLoading(true);
    try {
      const result = await loadSettings(getToken);
      setSettings(result.settings);
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    } finally {
      setSettingsLoading(false);
    }
  }

  function resolveChatStorageKey(scanId) {
    return scanId ? `scanChatHistory:${scanId}` : 'scanChatHistory:global';
  }

  async function handleSaveSettings() {
    if (!settings) return;
    setSettingsBusy(true);
    try {
      const result = await saveSettings(settings, getToken);
      setSettings(result.settings);
      setNotice({ type: 'success', message: 'Settings updated.' });
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
    } finally {
      setSettingsBusy(false);
    }
  }

  useEffect(() => {
    const key = resolveChatStorageKey(selectedScanId);
    setChatStorageKey(key);
    try {
      const saved = JSON.parse(window.localStorage.getItem(key) || '[]');
      setChatMessages(Array.isArray(saved) ? saved : []);
    } catch (error) {
      setChatMessages([]);
    }
  }, [selectedScanId]);

  useEffect(() => {
    window.localStorage.setItem(chatStorageKey, JSON.stringify(chatMessages));
  }, [chatMessages, chatStorageKey]);

  async function handleSendChat() {
    if (!chatInput.trim()) return;
    setChatBusy(true);

    const nextMessage = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      role: 'user',
      text: chatInput.trim(),
      createdAt: new Date().toISOString()
    };

    setChatMessages((prev) => {
      const updated = [...prev, nextMessage];
      setSelectedChatHistoryId(nextMessage.id);
      return updated;
    });
    const payload = {
      question: chatInput.trim()
    };

    if (selectedScan?.id) {
      payload.scanId = selectedScan.id;
    }

    setChatInput('');

    try {
      const result = await sendChatQuestion(payload, getToken);
      const assistantResponse = {
        id: `${Date.now() + 1}-${Math.random().toString(36).slice(2, 8)}`,
        role: 'assistant',
        text: result.answer || 'No answer was returned by the AI service.',
        createdAt: new Date().toISOString()
      };
      setChatMessages((prev) => {
        const updated = [...prev, assistantResponse];
        setSelectedChatHistoryId(assistantResponse.id);
        return updated;
      });
    } catch (error) {
      setNotice({ type: 'error', message: error.message });
      setChatMessages((prev) => {
        const errorMessage = {
          id: `${Date.now() + 1}-${Math.random().toString(36).slice(2, 8)}`,
          role: 'assistant',
          text: `Unable to get AI response: ${error.message}`,
          createdAt: new Date().toISOString()
        };
        setSelectedChatHistoryId(errorMessage.id);
        return [...prev, errorMessage];
      });
    } finally {
      setChatBusy(false);
    }
  }

  function handleClearChat() {
    setChatMessages([]);
    setSelectedChatHistoryId(null);
    window.localStorage.removeItem(chatStorageKey);
  }

  useEffect(() => {
    loadScans();
    loadAdminSummary();
    loadAuditLogs();
    loadManagedUsers();
    loadAppSettings();
  }, [role]);

  useEffect(() => {
    if (role === 'admin') {
      loadAuditLogs();
    }
  }, [auditFilters, role]);

  useEffect(() => {
    loadScan(selectedScanId);
  }, [selectedScanId]);

  useEffect(() => {
    const hasActiveScan = scans.some((scan) => ['queued', 'running'].includes(scan.status));
    const selectedActive = ['queued', 'running'].includes(selectedScan?.status);

    if (!hasActiveScan && !selectedActive) {
      return undefined;
    }

    const interval = window.setInterval(() => {
      loadScans();
      if (selectedScanId) {
        loadScan(selectedScanId);
      }
    }, 3000);

    return () => window.clearInterval(interval);
  }, [scans, selectedScan?.status, selectedScanId]);

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <strong>{currentUser.email}</strong>
          <span>{role === 'admin' ? 'Administrator' : 'Standard user'}</span>
        </div>
        <div className="workspace-tabs" role="tablist" aria-label="Workspace">
          <button
            className={activeWorkspace === 'welcome' ? 'active' : ''}
            onClick={() => setActiveWorkspace('welcome')}
          >
            Welcome
          </button>
          <button
            className={activeWorkspace === 'dashboard' ? 'active' : ''}
            onClick={() => setActiveWorkspace('dashboard')}
          >
            Dashboard
          </button>
          <button
            className={activeWorkspace === 'chat' ? 'active' : ''}
            onClick={() => setActiveWorkspace('chat')}
          >
            Chat
          </button>
          <button
            className={activeWorkspace === 'settings' ? 'active' : ''}
            onClick={() => setActiveWorkspace('settings')}
          >
            Settings
          </button>
          {role === 'admin' && (
            <button
              className={activeWorkspace === 'admin' ? 'active' : ''}
              onClick={() => setActiveWorkspace('admin')}
            >
              Admin
            </button>
          )}
        </div>
        <div className="topbar-actions">
          <UserButton />
          <button className="logout-button" onClick={() => signOut()}>
            <LogOut size={16} />
            Logout
          </button>
        </div>
      </header>

      {notice && (
        <div className={`toast ${notice.type}`}>
          {notice.type === 'error' ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
          <span>{notice.message}</span>
          <button onClick={() => setNotice(null)}>Dismiss</button>
        </div>
      )}

      {activeWorkspace === 'welcome' && (
        <WelcomePanel currentUser={currentUser} role={role} onNavigate={setActiveWorkspace} />
      )}

      {activeWorkspace === 'dashboard' && (
        <>
          <UploadPanel
            onScanCreated={handleScanCreated}
            busy={busy}
            setBusy={setBusy}
            setNotice={setNotice}
            getToken={getToken}
            currentUser={currentUser}
          />

          <section className="dashboard-context">
            <div>
              <span>Dashboard</span>
              <strong>Your scan, export, and reporting workflow</strong>
            </div>
            <p>
              Use this workspace to queue repositories, view scan results, and export security reports.
            </p>
          </section>

          <div className="content-grid">
            <div className="left-stack">
              <ScanHistory
                scans={scans}
                selectedScanId={selectedScanId}
                onSelectScan={setSelectedScanId}
                onRefresh={loadScans}
                loading={loading}
                isAdmin={role === 'admin'}
              />
            </div>
            <ReportPanel
              scan={selectedScan}
              loading={loading}
              getToken={getToken}
              setNotice={setNotice}
              onExported={loadAuditLogs}
            />
          </div>
        </>
      )}

      {activeWorkspace === 'chat' && (
        <div className="chat-workspace">
          <ConversationHistorySidebar
            chatMessages={chatMessages}
            selectedMessageId={selectedChatHistoryId}
            onSelectMessage={setSelectedChatHistoryId}
            onNewChat={handleClearChat}
          />
          <div className="chat-main">
            <ChatPanel
              selectedScan={selectedScan}
              chatMessages={chatMessages}
              draft={chatInput}
              setDraft={setChatInput}
              onSend={handleSendChat}
              onClear={handleClearChat}
              chatBusy={chatBusy}
            />
          </div>
        </div>
      )}

      {activeWorkspace === 'settings' && (
        <SettingsPanel
          currentUser={currentUser}
          settings={settings}
          busy={settingsBusy}
          onSave={handleSaveSettings}
          setSettings={setSettings}
        />
      )}

      {activeWorkspace === 'admin' && role === 'admin' ? (
        <div className="admin-dashboard-grid">
          <AdminPanel summary={adminSummary} isAdmin={role === 'admin'} loading={loading} />
          <UsersManagementPanel
            users={managedUsers}
            isAdmin={role === 'admin'}
            getToken={getToken}
            setNotice={setNotice}
            onChanged={() => {
              loadManagedUsers();
              loadAuditLogs();
            }}
          />
          <AuditLogPanel
            auditLogs={auditLogs}
            isAdmin={role === 'admin'}
            auditFilters={auditFilters}
            setAuditFilters={setAuditFilters}
          />
        </div>
      ) : null}
    </main>
  );
}

function App() {
  if (!CLERK_PUBLISHABLE_KEY) {
    return <AuthSetupNotice />;
  }

  return (
    <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY}>
      <SignedOut>
        <SignInScreen />
      </SignedOut>
      <SignedIn>
        <DashboardApp />
      </SignedIn>
    </ClerkProvider>
  );
}

createRoot(document.getElementById('root')).render(<App />);

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  ClerkProvider,
  useSignIn,
  useSession,
  AuthenticateWithRedirectCallback
} from '@clerk/clerk-react';
import {
  AlertTriangle,
  ArrowRight,
  BarChart2,
  Bot,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Download,
  FileArchive,
  FileText,
  GitBranch,
  GitPullRequest,
  Github,
  Lock,
  LogOut,
  MessageCircle,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  Upload,
  Users,
  XCircle,
  Zap
} from 'lucide-react';
import './styles.css';

/* ─── Constants ────────────────────────────────────────────── */
const API_BASE_URL       = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000';
const CLERK_PUB_KEY      = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY;
const SESSION_STORAGE_KEY = 'aiCodeSecurityReviewerSession';
const severityOrder      = ['critical', 'high', 'medium', 'low', 'info'];

/* ─── Helpers ──────────────────────────────────────────────── */
function formatDate(v) {
  if (!v) return 'Not started';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(v));
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
      const sev = String(item.severity || 'info').toLowerCase();
      acc[sev] = (acc[sev] || 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );
}

/* ─── API ──────────────────────────────────────────────────── */
async function getAuthHeaders(getToken) {
  const token = await getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function submitAuth(path, payload) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.error?.message || `Authentication failed (${res.status})`);
  }
  return res.json();
}

async function apiGet(path, getToken) {
  const res = await fetch(`${API_BASE_URL}${path}`, { headers: await getAuthHeaders(getToken) });
  if (!res.ok) throw new Error(`Request failed (${res.status})`);
  return res.json();
}

async function apiPatch(path, body, getToken) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: 'PATCH',
    headers: { ...(await getAuthHeaders(getToken)), 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!res.ok) {
    const p = await res.json().catch(() => null);
    throw new Error(p?.error?.message || `Request failed (${res.status})`);
  }
  return res.json();
}

async function downloadScanPdf(scan, getToken) {
  const res = await fetch(`${API_BASE_URL}/api/scans/${scan.id}/export.pdf`, {
    headers: await getAuthHeaders(getToken)
  });
  if (!res.ok) throw new Error(`PDF export failed (${res.status})`);
  const blob = await res.blob();
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href: url, download: `${scan.project_name}-security-report.pdf` });
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

async function loadSettings(getToken)          { const r = await fetch(`${API_BASE_URL}/api/settings`, { headers: await getAuthHeaders(getToken) }); if (!r.ok) throw new Error(`Settings failed (${r.status})`); return r.json(); }
async function saveSettings(payload, getToken) { const r = await fetch(`${API_BASE_URL}/api/settings`, { method:'PATCH', headers:{...(await getAuthHeaders(getToken)),'Content-Type':'application/json'}, body:JSON.stringify(payload) }); if (!r.ok) { const b=await r.json().catch(()=>null); throw new Error(b?.error?.message||`Settings failed (${r.status})`); } return r.json(); }
async function sendChatQuestion(payload, getToken) { const r = await fetch(`${API_BASE_URL}/api/scans/chat`, { method:'POST', headers:{...(await getAuthHeaders(getToken)),'Content-Type':'application/json'}, body:JSON.stringify(payload) }); if (!r.ok) { const b=await r.json().catch(()=>null); throw new Error(b?.error?.message||`Chat failed (${r.status})`); } return r.json(); }
async function requestSecurePatch(scanId, findingId, getToken) {
  const r = await fetch(`${API_BASE_URL}/api/scans/${scanId}/findings/${findingId}/secure-patch`, {
    method:'POST', headers:{...(await getAuthHeaders(getToken)),'Content-Type':'application/json'}, body:'{}'
  });
  if (!r.ok) { const b=await r.json().catch(()=>null); throw new Error(b?.error?.message||`AI fix failed (${r.status})`); }
  return r.json();
}

/* ─── Status Badge ─────────────────────────────────────────── */
function StatusBadge({ status }) {
  const map = { queued:{Icon:Clock3,label:'Queued'}, running:{Icon:RefreshCw,label:'Running'}, completed:{Icon:CheckCircle2,label:'Completed'}, failed:{Icon:XCircle,label:'Failed'} };
  const { Icon, label } = map[status] || map.queued;
  return <span className={`status-badge status-${status}`}><Icon size={11}/>{label}</span>;
}

/* ─── Progress Bar ─────────────────────────────────────────── */
function ProgressBar({ value }) {
  const p = Math.max(0, Math.min(100, value ?? 0));
  return (
    <div className="progress-bar" aria-label={`${p}%`}>
      <div className="progress-bar-fill" style={{ width:`${p}%` }}/>
      <span className="progress-bar-text">{p}%</span>
    </div>
  );
}

/* ─── Score Ring ───────────────────────────────────────────── */
function ScoreRing({ score }) {
  const d     = typeof score === 'number' ? score : 0;
  const angle = Math.max(0, Math.min(100, d)) * 3.6;
  const color = d >= 80 ? 'var(--success)' : d >= 50 ? 'var(--warning)' : 'var(--critical)';
  return (
    <div className="score-ring"
      style={{ background:`conic-gradient(${color} ${angle}deg,rgba(255,255,255,0.07) ${angle}deg)` }}
      aria-label={`Security score ${d}/100`}>
      <div className="score-ring-inner">
        <strong style={{ color }}>{typeof score==='number'?score:'—'}</strong>
        <span>/100</span>
      </div>
    </div>
  );
}

/* ─── Severity Chart ───────────────────────────────────────── */
function severityBucket(sev) {
  const s = String(sev || '').toLowerCase();
  if (['critical', 'high'].includes(s)) return 'high';
  if (['medium'].includes(s)) return 'medium';
  if (['low', 'info'].includes(s)) return 'low';
  return 'low';
}

function SeverityChart({ counts }) {
  const bucketCounts = severityOrder.reduce((acc, sev) => {
    const b = severityBucket(sev);
    acc[b] = (acc[b] || 0) + (counts[sev] || 0);
    return acc;
  }, { high: 0, medium: 0, low: 0 });

  const total = bucketCounts.high + bucketCounts.medium + bucketCounts.low;
  if (!total) return <div className="empty-state">No severity findings to display.</div>;

  const clr = { high: 'var(--critical)', medium: 'var(--medium)', low: 'var(--low)' };
  const labelMap = { high: 'High', medium: 'Medium', low: 'Low' };

  return (
    <div className="severity-chart">
      <div className="severity-chart-header"><span>Severity (High/Medium/Low)</span><strong>{total} findings</strong></div>
      {['high','medium','low'].map(sev => {
        const count = bucketCounts[sev] || 0;
        return (
          <div key={sev} className="severity-chart-row">
            <span className="severity-chart-label" style={{ color: clr[sev] }}>{labelMap[sev]}</span>
            <div className="severity-chart-track">
              <div className="severity-chart-fill" style={{ width: total ? `${(count/total)*100}%` : '0%', background: clr[sev] }} />
            </div>
            <span className="severity-chart-count">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

const SEVERITY_TIERS = [
  { key: 'high',   label: 'High Severity',   blurb: 'Exploitable now — fix immediately', color: 'var(--critical)', includes: ['critical', 'high'] },
  { key: 'medium', label: 'Medium Severity', blurb: 'Should be remediated soon',          color: 'var(--medium)',   includes: ['medium'] },
  { key: 'low',    label: 'Low Severity',    blurb: 'Best-practice / hardening',            color: 'var(--low)',      includes: ['low', 'info'] }
];

function SeverityCategoryCards({ counts }) {
  const tierCounts = SEVERITY_TIERS.map((tier) => ({
    ...tier,
    count: tier.includes.reduce((sum, sev) => sum + (counts[sev] || 0), 0)
  }));
  return (
    <div className="severity-cards">
      {tierCounts.map((tier) => (
        <div key={tier.key} className={`severity-card severity-card-${tier.key}`}>
          <div className="severity-card-top">
            <span className="severity-card-dot" style={{ background: tier.color }} />
            <span className="severity-card-label" style={{ color: tier.color }}>{tier.label}</span>
          </div>
          <strong className="severity-card-count" style={{ color: tier.color }}>{tier.count}</strong>
          <span className="severity-card-blurb">{tier.blurb}</span>
        </div>
      ))}
    </div>
  );
}

function escapeHtml(str) {
  return String(str ?? '')
    .replaceAll('&','&amp;')
    .replaceAll('<','<')
    .replaceAll('>','>')
    .replaceAll('"','"')
    .replaceAll("'",'&#039;');
}

function buildPrintHtml(scan, vulnerabilities) {
  const now = new Date().toISOString();
  const counts = getSeverityCounts(vulnerabilities || []);
  const high = (counts.critical || 0) + (counts.high || 0);
  const medium = counts.medium || 0;
  const low = (counts.low || 0) + (counts.info || 0);

  const tierMeta = [
    { key: 'high',   label: 'High Severity',   color: '#d12c3b', includes: ['critical', 'high'] },
    { key: 'medium', label: 'Medium Severity', color: '#b9770a', includes: ['medium'] },
    { key: 'low',    label: 'Low Severity',    color: '#2f6bd1', includes: ['low', 'info'] }
  ];

  const renderFinding = (v) => {
    const secure = v.secure_patch ?? v.securePatch ?? '';
    return `
      <div class="card finding">
        <div><span class="sev">${escapeHtml(v.severity || 'info').toUpperCase()}</span> — <strong>${escapeHtml(v.title || 'Untitled')}</strong></div>
        ${v.file_path ? `<div style="color:#666;font-size:12px;margin-top:6px;">${escapeHtml(v.file_path)}${v.line_start?`:${v.line_start}`:''}</div>` : ''}
        ${v.description ? `<div style="margin-top:8px;">${escapeHtml(v.description)}</div>` : ''}
        ${v.recommendation ? `<div style="margin-top:8px;"><strong>Remediation</strong><div>${escapeHtml(v.recommendation)}</div></div>` : ''}
        ${v.evidence ? `<div style="margin-top:10px;"><strong>Evidence</strong><pre>${escapeHtml(v.evidence)}</pre></div>` : ''}
        ${secure ? `<div style="margin-top:10px;"><strong>Secure patch (AI)</strong><pre>${escapeHtml(secure)}</pre></div>` : ''}
      </div>
    `;
  };

  const findingsHtml = tierMeta.map((tier) => {
    const items = (vulnerabilities || [])
      .filter((v) => tier.includes.includes(String(v.severity || 'info').toLowerCase()))
      .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));
    if (!items.length) return '';
    return `
      <h2 class="tier" style="border-left:6px solid ${tier.color};color:${tier.color};">${tier.label} <span style="color:#888;font-weight:600;">(${items.length})</span></h2>
      ${items.map(renderFinding).join('')}
    `;
  }).join('');

  return `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8"/>
        <title>${escapeHtml(scan?.project_name || 'Security Report')}</title>
        <style>
          body { font-family: Inter, Arial, sans-serif; padding: 24px; }
          h1 { margin:0 0 6px; font-size: 22px; }
          .meta { color:#444; font-size: 12px; margin-bottom: 14px; }
          .strip { display:flex; gap: 10px; margin: 10px 0 18px; }
          .pill { padding: 8px 10px; border-radius: 12px; border: 1px solid #ddd; font-weight: 800; }
          .high { background:#ffecec; border-color:#ffb3b3; }
          .medium { background:#fff3db; border-color:#ffe2a8; }
          .low { background:#e9f1ff; border-color:#bcd1ff; }
          .tier { font-size:15px; margin:22px 0 6px; padding:6px 0 6px 12px; }
          .card { border:1px solid #e5e5e5; border-radius:14px; padding:14px; margin: 12px 0; }
          .sev { font-weight: 800; }
          pre { background:#0b0b0b; color:#d7ffd9; padding: 10px; border-radius: 10px; overflow-x: auto; }
          @media print { body { padding: 0; } .no-print { display:none; } }
        </style>
      </head>
      <body>
        <div class="no-print" style="margin-bottom:14px;">
          <button onclick="window.print()" style="padding:10px 14px;border-radius:10px;border:1px solid #ddd;background:#f7f7f7;cursor:pointer;">Print / Save PDF</button>
        </div>
        <h1>ShieldAI Security Report</h1>
        <div class="meta">Project: <strong>${escapeHtml(scan?.project_name || '')}</strong> · Created: <strong>${escapeHtml(scan?.created_at ? formatDate(scan.created_at) : '—')}</strong></div>
        <div class="strip">
          <div class="pill high">High: ${high}</div>
          <div class="pill medium">Medium: ${medium}</div>
          <div class="pill low">Low: ${low}</div>
        </div>
        ${findingsHtml}
        <div class="meta" style="margin-top:18px;">Generated at: ${escapeHtml(now)}</div>
      </body>
    </html>
  `;
}


/* ─── Skeletons ────────────────────────────────────────────── */
function SkeletonScanList()  { return <div className="scan-list">{[1,2,3].map(i=><div key={i} className="skeleton skeleton-scan-row"/>)}</div>; }
function SkeletonReport()    { return <div style={{display:'grid',gap:12}}><div className="skeleton skeleton-report-block"/><div className="skeleton" style={{height:80}}/><div className="skeleton" style={{height:120}}/></div>; }

/* ─── Upload Panel ─────────────────────────────────────────── */
function UploadPanel({ onScanCreated, busy, setBusy, setNotice, getToken, currentUser }) {
  const [file,   setFile]   = useState(null);
  const [repoUrl,setRepoUrl]= useState('');
  const [orgId,  setOrgId]  = useState('');
  const [teamId, setTeamId] = useState('');

  async function handleZip(e) {
    e.preventDefault();
    if (!file) { setNotice({ type:'error', message:'Choose a ZIP repository first.' }); return; }
    setBusy(true);
    try {
      const form = new FormData();
      form.append('repository', file);
      if (orgId)  form.append('organizationId', orgId);
      if (teamId) form.append('teamId', teamId);
      const res = await fetch(`${API_BASE_URL}/api/scans/zip`, { method:'POST', headers:await getAuthHeaders(getToken), body:form });
      if (!res.ok) { const b=await res.json().catch(()=>null); throw new Error(b?.error?.message||`Upload failed (${res.status})`); }
      const result = await res.json();
      setNotice({ type:'success', message:'ZIP scan queued.' });
      onScanCreated(result.scan.id); setFile(null); e.target.reset();
    } catch(err) { setNotice({ type:'error', message:err.message }); }
    finally { setBusy(false); }
  }

  async function handleGithub(e) {
    e.preventDefault();
    if (!repoUrl.trim()) { setNotice({ type:'error', message:'Paste a GitHub URL first.' }); return; }
    setBusy(true);
    try {
      const payload = { repositoryUrl:repoUrl.trim() };
      if (orgId) payload.organizationId=orgId;
      if (teamId) payload.teamId=teamId;
      const res = await fetch(`${API_BASE_URL}/api/scans/github`, { method:'POST', headers:{...(await getAuthHeaders(getToken)),'Content-Type':'application/json'}, body:JSON.stringify(payload) });
      if (!res.ok) { const b=await res.json().catch(()=>null); throw new Error(b?.error?.message||`GitHub scan failed (${res.status})`); }
      const result = await res.json();
      setNotice({ type:'success', message:'GitHub scan queued.' });
      onScanCreated(result.scan.id); setRepoUrl('');
    } catch(err) { setNotice({ type:'error', message:err.message }); }
    finally { setBusy(false); }
  }

  return (
    <section className="panel upload-panel">
      <div className="panel-heading">
        <div className="panel-heading-icon"><Shield size={20}/></div>
        <div>
          <h1>ShieldAI Reviewer</h1>
          <p>{currentUser.email} · {currentUser.role==='admin'?'Administrator':'User'}</p>
        </div>
      </div>

      <form className="upload-box" onSubmit={handleZip}>
        <div className="upload-title"><FileArchive size={15}/><h2>ZIP Upload</h2></div>
        <label className={`file-drop ${file?'has-file':''}`}>
          <Upload size={17}/>
          <span>{file?file.name:'Drop or browse a repository ZIP'}</span>
          <input type="file" accept=".zip" onChange={e=>setFile(e.target.files?.[0]||null)}/>
        </label>
        <input type="text" placeholder="Organization ID (optional)" value={orgId}   onChange={e=>setOrgId(e.target.value)}/>
        <input type="text" placeholder="Team ID (optional)"         value={teamId}  onChange={e=>setTeamId(e.target.value)}/>
        <button type="submit" disabled={busy}><Upload size={13}/>{busy?'Queuing…':'Queue ZIP Scan'}</button>
      </form>

      <form className="upload-box" onSubmit={handleGithub}>
        <div className="upload-title"><Github size={15}/><h2>GitHub Repository</h2></div>
        <input type="url"  placeholder="https://github.com/org/repo" value={repoUrl} onChange={e=>setRepoUrl(e.target.value)}/>
        <input type="text" placeholder="Organization ID (optional)"   value={orgId}   onChange={e=>setOrgId(e.target.value)}/>
        <input type="text" placeholder="Team ID (optional)"           value={teamId}  onChange={e=>setTeamId(e.target.value)}/>
        <button type="submit" disabled={busy}><Github size={13}/>{busy?'Queuing…':'Queue GitHub Scan'}</button>
      </form>
    </section>
  );
}

/* ─── Scan History ─────────────────────────────────────────── */
function ScanHistory({ scans, selectedScanId, onSelectScan, onRefresh, loading, isAdmin }) {
  return (
    <section className="panel history-panel">
      <div className="section-header">
        <div>
          <h2>{isAdmin?'All Scan History':'Your Scan History'}</h2>
          <p>{scans.length} {isAdmin?'platform':'account'} scans</p>
        </div>
        <button className="icon-button" onClick={onRefresh} disabled={loading} title="Refresh"><RefreshCw size={14}/></button>
      </div>

      {loading && scans.length===0 ? <SkeletonScanList/> :
       scans.length===0 ? (
        <div className="empty-state">
          <div className="empty-state-icon"><FileText size={32}/></div>
          <div className="empty-state-title">No scans yet</div>
          <div className="empty-state-desc">Queue your first repository above.</div>
        </div>
       ) : (
        <div className="scan-list">
          {scans.map(scan => {
            const counts = getSeverityCounts(scan.vulnerabilities||[]);
            return (
              <button key={scan.id}
                className={`scan-row ${selectedScanId===scan.id?'selected':''} status-${scan.status}`}
                onClick={()=>onSelectScan(scan.id)}>
                <div>
                  <strong>{scan.project_name}</strong>
                  <span>{formatDate(scan.created_at)}</span>
                  {(scan.organizationId||scan.teamId) && (
                    <span className="muted">
                      {[scan.organizationId&&`Org: ${scan.organizationId}`,scan.teamId&&`Team: ${scan.teamId}`].filter(Boolean).join(' · ')}
                    </span>
                  )}
                  {scan.vulnerabilityCount>0 && (
                    <div className="scan-severity-dots">
                      {severityOrder.map(sev=>counts[sev]>0?<span key={sev} className={`sev-dot ${sev}`} title={`${counts[sev]} ${sev}`}/>:null)}
                    </div>
                  )}
                </div>
                <div className="scan-row-meta">
                  <StatusBadge status={scan.status}/>
                  <span style={{fontSize:11,color:'var(--text-3)'}}>{scan.vulnerabilityCount} findings</span>
                  <ProgressBar value={scan.progress}/>
                </div>
              </button>
            );
          })}
        </div>
       )}
    </section>
  );
}

/* ─── Line diff (LCS) for side-by-side code compare ────────── */
function diffLines(aText, bText) {
  const a = String(aText || '').replace(/\r\n/g, '\n').split('\n');
  const b = String(bText || '').replace(/\r\n/g, '\n').split('\n');
  const n = a.length;
  const m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const left = [];
  const right = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      left.push({ t: 'equal', text: a[i] }); right.push({ t: 'equal', text: b[j] }); i++; j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      left.push({ t: 'remove', text: a[i] }); right.push({ t: 'spacer', text: '' }); i++;
    } else {
      left.push({ t: 'spacer', text: '' }); right.push({ t: 'add', text: b[j] }); j++;
    }
  }
  while (i < n) { left.push({ t: 'remove', text: a[i] }); right.push({ t: 'spacer', text: '' }); i++; }
  while (j < m) { left.push({ t: 'spacer', text: '' }); right.push({ t: 'add', text: b[j] }); j++; }
  return { left, right };
}

function DiffColumn({ rows }) {
  return (
    <pre className="code-pre diff-pre">
      {rows.map((row, idx) => (
        <div key={idx} className={`diff-line diff-${row.t}`}>{row.text === '' ? '\u00A0' : row.text}</div>
      ))}
    </pre>
  );
}

/* ─── Collapsible Finding ──────────────────────────────────── */
function SecuredPatchView({ finding, scanId, getToken }) {
  const insecure = finding?.evidence || '';
  const [secure, setSecure] = useState(finding?.secure_patch ?? finding?.securePatch ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setSecure(finding?.secure_patch ?? finding?.securePatch ?? '');
    setError('');
  }, [finding?.id]);

  const hasSecure = Boolean(String(secure).trim());
  const diff = hasSecure ? diffLines(insecure, secure) : null;

  const onGenerate = async () => {
    if (!scanId || !finding?.id) {
      setError('Cannot generate a fix for this finding.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const res = await requestSecurePatch(scanId, finding.id, getToken);
      const patch = res.securePatch || '';
      setSecure(patch);
      if (!String(patch).trim()) {
        setError('AI did not return a patch for this finding.');
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="code-compare">
      <div className="code-compare-header">
        <div className="code-compare-title">Automated AI Remediation &amp; Code Compare</div>
        <div className="code-compare-subtitle">
          <span className="cmp-label cmp-insecure">Insecure</span>
          <span className="cmp-sep">→</span>
          <span className="cmp-label cmp-secure">Secure patch</span>
        </div>
      </div>

      {error && <div className="notice error" style={{ marginBottom: 10 }}><AlertTriangle size={14}/>{error}</div>}

      {!hasSecure ? (
        <div className="empty-state" style={{ minHeight: 90 }}>
          <div className="empty-state-title">No AI secure patch yet</div>
          <div className="empty-state-desc">Generate a secured code snippet for this finding using your AI provider.</div>
          <button type="button" className="primary-action" style={{ marginTop: 12 }} disabled={busy} onClick={onGenerate}>
            {busy ? <><RefreshCw size={14} className="spin"/>Generating…</> : <><Zap size={14}/>Generate AI fix</>}
          </button>
        </div>
      ) : (
        <>
          <div className="code-compare-grid">
            <div className="code-compare-col code-col-insecure">
              <div className="code-compare-col-title">Insecure code</div>
              <DiffColumn rows={diff.left}/>
            </div>
            <div className="code-compare-col code-col-secure">
              <div className="code-compare-col-title">Secure code (AI)</div>
              <DiffColumn rows={diff.right}/>
            </div>
          </div>
          <button type="button" className="secondary-action" style={{ marginTop: 10 }} disabled={busy} onClick={onGenerate}>
            {busy ? <><RefreshCw size={13} className="spin"/>Regenerating…</> : <><RefreshCw size={13}/>Regenerate AI fix</>}
          </button>
        </>
      )}
    </div>
  );
}

function FindingCard({ finding, scanId, getToken }) {
  const [open, setOpen] = useState(false);
  return (
    <article className={`finding severity-${finding.severity} ${open?'open':''}`}>
      <div className="finding-header" onClick={()=>setOpen(o=>!o)} role="button" tabIndex={0}
        onKeyDown={e=>e.key==='Enter'&&setOpen(o=>!o)}>
        <div className="finding-topline">
          <span className="severity-pill">{finding.severity}</span>
          <strong>{finding.title}</strong>
        </div>
        <ChevronDown size={15} className="finding-chevron"/>
      </div>
      <div className="finding-body">
        <div className="finding-body-inner">
          {finding.file_path && <div className="finding-location">{finding.file_path}{finding.line_start?`:${finding.line_start}`:''}</div>}
          {finding.description && <p>{finding.description}</p>}
          {finding.recommendation && <div className="recommendation"><span>Remediation</span><p>{finding.recommendation}</p></div>}

          {/* Modern side-by-side AI remediation diff view */}
          <SecuredPatchView finding={finding} scanId={scanId} getToken={getToken} />
        </div>
      </div>
    </article>
  );
}

/* ─── Vulnerability Table ──────────────────────────────────── */
function VulnerabilityTable({ vulnerabilities, scanId, getToken }) {
  const groups = useMemo(() => {
    return SEVERITY_TIERS.map((tier) => ({
      ...tier,
      items: [...vulnerabilities]
        .filter((v) => tier.includes.includes(String(v.severity || 'info').toLowerCase()))
        .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
    })).filter((g) => g.items.length > 0);
  }, [vulnerabilities]);

  if (!vulnerabilities.length) return (
    <div className="empty-state">
      <div className="empty-state-icon"><CheckCircle2 size={32}/></div>
      <div className="empty-state-title">No vulnerabilities found</div>
      <div className="empty-state-desc">This scan completed with no recorded security findings.</div>
    </div>
  );
  return (
    <div className="vulnerability-groups">
      {groups.map((group) => (
        <section key={group.key} className={`severity-group severity-group-${group.key}`}>
          <header className="severity-group-header" style={{ borderColor: group.color }}>
            <span className="severity-group-dot" style={{ background: group.color }} />
            <h3 style={{ color: group.color }}>{group.label}</h3>
            <span className="severity-group-count">{group.items.length}</span>
          </header>
          <div className="vulnerability-list">
            {group.items.map((f) => <FindingCard key={f.id} finding={f} scanId={scanId} getToken={getToken}/>)}
          </div>
        </section>
      ))}
    </div>
  );
}

/* ─── Report Panel ─────────────────────────────────────────── */
function ReportPanel({ scan, loading, getToken, setNotice, onExported }) {
  if (loading && !scan) return <section className="panel report-panel"><SkeletonReport/></section>;
  if (!scan) return (
    <section className="panel report-panel" style={{display:'grid',alignItems:'center'}}>
      <div className="empty-state">
        <div className="empty-state-icon"><Shield size={36}/></div>
        <div className="empty-state-title">No scan selected</div>
        <div className="empty-state-desc">Select a scan or queue a repository to view its security report.</div>
      </div>
    </section>
  );
  const vulns = scan.vulnerabilities||[];
  return (
    <section className="panel report-panel">
      <div className="report-header">
        <div>
          <div className="report-kicker">Security Report</div>
          <h2>{scan.project_name}</h2>
          <div className="report-meta">
            <StatusBadge status={scan.status}/>
            {scan.source_type&&<span>{scan.source_type}</span>}
            {scan.user_email&&<span>{scan.user_email}</span>}
            <span>{formatDate(scan.created_at)}</span>
            {scan.organizationId&&<span>Org: {scan.organizationId}</span>}
            {scan.teamId&&<span>Team: {scan.teamId}</span>}
          </div>
          <div style={{marginTop:10}}><ProgressBar value={scan.progress}/></div>
        </div>
        <div className="report-actions">
          <button className="secondary-action" onClick={async()=>{
            try {
              await downloadScanPdf(scan,getToken);
              setNotice({type:'success',message:'PDF exported.'});
              onExported();
            } catch(err) {
              setNotice({type:'error',message:err.message});
            }
          }}><Download size={13}/>Export PDF</button>
          <button className="secondary-action" onClick={()=>{
            try {
              const html = buildPrintHtml(scan, vulns);
              const blob = new Blob([html], { type: 'text/html' });
              const url  = URL.createObjectURL(blob);
              const w = window.open(url, '_blank');
              if (!w) throw new Error('Popup blocked. Please allow popups for this site.');
              setTimeout(()=>URL.revokeObjectURL(url), 60000);
              setNotice({type:'success',message:'Report opened for printing.'});
            } catch (err) {
              setNotice({type:'error',message:err.message});
            }
          }}><FileText size={13}/>Export HTML</button>
          <ScoreRing score={scan.security_score}/>
        </div>
      </div>
      {scan.error_message&&<div className="notice error"><AlertTriangle size={14}/>{scan.error_message}</div>}
      <div className="summary-grid">
        <div><span>Total Findings</span><strong>{vulns.length}</strong></div>
        <div><span>Critical / High</span><strong>{vulns.filter(v=>['critical','high'].includes(v.severity)).length}</strong></div>
        <div><span>Completed</span><strong style={{fontSize:14}}>{scan.completed_at?formatDate(scan.completed_at):'—'}</strong></div>
      </div>
      <SeverityCategoryCards counts={getSeverityCounts(vulns)}/>
      <SeverityChart counts={getSeverityCounts(vulns)}/>
      <VulnerabilityTable vulnerabilities={vulns} scanId={scan.id} getToken={getToken}/>
    </section>
  );
}

/* ─── Chat Sidebar ─────────────────────────────────────────── */
function ConversationHistorySidebar({ chatMessages, selectedMessageId, onSelectMessage, onNewChat }) {
  return (
    <aside className="chat-sidebar">
      <div className="sidebar-top">
        <div className="sidebar-brand"><Bot size={17}/><div><strong>Security Chat</strong><span>AI assistant</span></div></div>
        <button type="button" className="new-chat-button" onClick={onNewChat}>+ New</button>
      </div>
      <div className="sidebar-list">
        {chatMessages.length===0
          ? <div className="empty-state" style={{minHeight:80}}><div style={{fontSize:12}}>Start a conversation</div></div>
          : chatMessages.map(msg=>(
            <button key={msg.id} type="button"
              className={`sidebar-item ${selectedMessageId===msg.id?'selected':''}`}
              onClick={()=>onSelectMessage(msg.id)}>
              <span className="sidebar-role">{msg.role==='assistant'?'AI':'You'}</span>
              <span className="sidebar-snippet">{msg.text.slice(0,72)}{msg.text.length>72?'…':''}</span>
              <span className="sidebar-time">{formatDate(msg.createdAt)}</span>
            </button>
          ))}
      </div>
    </aside>
  );
}

/* ─── Chat Panel ───────────────────────────────────────────── */
function ChatPanel({ selectedScan, chatMessages, draft, setDraft, onSend, onClear, chatBusy }) {
  const bottomRef = useRef(null);
  const disabled  = chatBusy || !draft.trim() || !selectedScan;
  const count     = selectedScan ? (selectedScan.vulnerability_count ?? selectedScan.vulnerabilities?.length ?? 0) : 0;

  useEffect(()=>{ bottomRef.current?.scrollIntoView({behavior:'smooth',block:'end'}); },[chatMessages,chatBusy]);

  return (
    <section className="panel chat-panel">
      <div className="chat-header">
        <div><h2>Chat with Security AI</h2><p>AI-guided remediation, context-aware to your scan.</p></div>
        <div className="chat-header-info">
          <span>{selectedScan?selectedScan.project_name:'No scan selected'}</span>
          <span>{selectedScan?`${count} findings`:'Select a scan to begin'}</span>
        </div>
      </div>
      <div className="chat-thread" role="log" aria-live="polite">
        {chatMessages.length===0&&!chatBusy&&(
          <div className="empty-state" style={{minHeight:180,alignContent:'center'}}>
            <div className="empty-state-icon"><Bot size={30}/></div>
            <div className="empty-state-title">Ask the Security AI</div>
            <div className="empty-state-desc">
              {selectedScan?`Ask about "${selectedScan.project_name}" — vulnerabilities, fixes, impact.`:'Select a scan first, then start chatting.'}
            </div>
          </div>
        )}
        {chatMessages.map(msg=>(
          <article key={msg.id} className={`chat-message chat-${msg.role}`}>
            <div className="chat-message-bubble">
              <div className="chat-message-header">
                <span className="chat-role">{msg.role==='assistant'?'Security AI':'You'}</span>
                <span className="chat-time">{formatDate(msg.createdAt)}</span>
              </div>
              <p>{msg.text}</p>
            </div>
          </article>
        ))}
        {chatBusy&&(
          <article className="chat-message chat-assistant">
            <div className="chat-message-bubble">
              <div className="chat-message-header"><span className="chat-role">Security AI</span></div>
              <div className="typing-dots"><span/><span/><span/></div>
            </div>
          </article>
        )}
        <div ref={bottomRef}/>
      </div>
      <form className="chat-entry" onSubmit={e=>{e.preventDefault();onSend();}}>
        <textarea value={draft} rows={3}
          placeholder={selectedScan?'Ask a question… (Ctrl+Enter to send)':'Select a scan to use AI chat.'}
          onChange={e=>setDraft(e.target.value)}
          onKeyDown={e=>{if(e.key==='Enter'&&(e.ctrlKey||e.metaKey)&&!disabled)onSend();}}
          disabled={chatBusy||!selectedScan}/>
        <div className="chat-actions">
          <button type="submit" className="primary-action" disabled={disabled}>{chatBusy?'Thinking…':'Send'}</button>
          <button type="button" className="secondary-action" onClick={onClear} disabled={chatBusy||!chatMessages.length}>Clear</button>
        </div>
      </form>
    </section>
  );
}

/* ─── Settings Panel ───────────────────────────────────────── */
function SettingsPanel({ currentUser, settings, busy, onSave, setSettings }) {
  if (!settings) return <section className="panel settings-panel"><div className="empty-state"><div>Loading settings…</div></div></section>;
  return (
    <section className="panel settings-panel">
      <div className="section-header"><div><h2>Settings &amp; Profile</h2><p>Account profile and AI model configuration.</p></div></div>
      <div className="profile-summary">
        <h3>Profile</h3>
        <div><span>Email</span><strong>{currentUser.email}</strong></div>
        <div><span>Role</span><strong><span className={`role-pill role-${currentUser.role}`}>{currentUser.role==='admin'?'Administrator':'User'}</span></strong></div>
      </div>
      <div className="model-settings">
        <h3>Model Integration</h3>
        {[
          {label:'AI Provider',key:'aiProvider',type:'select',opts:[['openai','OpenAI'],['ollama','Ollama (Local)'],['groq','GroqCloud']]},
          {label:'OpenAI Model',key:'openAiModel',type:'text'},
          {label:'Ollama Base URL',key:'ollamaBaseUrl',type:'url'},
          {label:'Ollama Model',key:'ollamaModel',type:'text'},
          {label:'GroqCloud Model',key:'groqModel',type:'text'},
          {label:'AI Analysis',key:'aiAnalysisEnabled',type:'select',opts:[['true','Enabled'],['false','Disabled']],isBoolean:true}
        ].map(({label,key,type,opts,isBoolean})=>(
          <label key={key}>
            {label}
            {type==='select' ? (
              <select value={isBoolean?String(settings[key]):settings[key]}
                onChange={e=>setSettings({...settings,[key]:isBoolean?e.target.value==='true':e.target.value})}
                disabled={busy||currentUser.role!=='admin'}>
                {opts.map(([v,l])=><option key={v} value={v}>{l}</option>)}
              </select>
            ) : (
              <input type={type} value={settings[key]||''}
                onChange={e=>setSettings({...settings,[key]:e.target.value})}
                disabled={busy||currentUser.role!=='admin'}/>
            )}
          </label>
        ))}
        <div className="settings-note">⚡ Runtime settings take effect immediately. Env vars set startup defaults.</div>
        {currentUser.role==='admin'&&<button type="button" className="secondary-action" disabled={busy} onClick={onSave}>{busy?'Saving…':'Save Settings'}</button>}
      </div>
    </section>
  );
}

/* ─── CI/CD Pipeline Blueprint (roadmap) ───────────────────── */
function PipelineBlueprint() {
  const steps = [
    { Icon: GitBranch,       title: 'Developer pushes code',  desc: 'Commit / open Pull Request on GitHub' },
    { Icon: Github,          title: 'GitHub Action triggers', desc: 'ShieldAI runs automatically in CI' },
    { Icon: ShieldCheck,     title: 'AI security scan',        desc: 'Static analysis + AI remediation' },
    { Icon: GitPullRequest,  title: 'Gate the merge',          desc: 'Block PR if Critical/High found' }
  ];
  const workflowYaml = `name: ShieldAI Security Review
on:
  pull_request:
    branches: [ main ]

jobs:
  shieldai-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run ShieldAI scan
        uses: shieldai/scan-action@v1
        with:
          fail-on: high   # block merge on Critical/High`;
  return (
    <section className="panel blueprint-panel">
      <div className="blueprint-head">
        <span className="blueprint-badge"><Zap size={11}/>Roadmap · CI/CD Integration</span>
        <h2>GitHub Action Blueprint</h2>
        <p>Shift security left — ShieldAI runs inside your pipeline so every push is scanned <strong>before</strong> it merges.</p>
      </div>
      <div className="pipeline-flow">
        {steps.map(({ Icon, title, desc }, i) => (
          <React.Fragment key={title}>
            <div className="pipeline-node">
              <div className="pipeline-node-icon"><Icon size={20}/></div>
              <strong>{title}</strong>
              <span>{desc}</span>
            </div>
            {i < steps.length - 1 && <ArrowRight className="pipeline-arrow" size={18}/>}
          </React.Fragment>
        ))}
      </div>
      <div className="blueprint-yaml">
        <div className="blueprint-yaml-head"><FileText size={13}/><span>.github/workflows/shieldai.yml</span><span className="blueprint-soon">Preview</span></div>
        <pre>{workflowYaml}</pre>
      </div>
    </section>
  );
}

/* ─── Welcome Panel ────────────────────────────────────────── */
function WelcomePanel({ currentUser, role, onNavigate, activeCount }) {
  const name = currentUser.email.split('@')[0] || currentUser.email;
  const features = [
    { Icon:Search,   title:'Deep Scanning', desc:'AI-powered static analysis across your entire codebase.' },
    { Icon:Bot,      title:'AI Chat',       desc:'Ask the AI about vulnerabilities and get fix recommendations.' },
    { Icon:FileText, title:'PDF Reports',   desc:'Professional security reports ready for stakeholders.' }
  ];
  return (
    <section className="panel welcome-panel">
      <div className="welcome-card">
        <div className="welcome-kicker"><Zap size={11}/>AI-Powered Security Analysis</div>
        <h1>Welcome back, <span className="accent-text">{name}</span>!</h1>
        <p>Scan repositories for vulnerabilities, review AI-generated security reports, and get context-aware remediation guidance.</p>
        <div className="welcome-features">
          {features.map(({Icon,title,desc})=>(
            <div key={title} className="welcome-feature-card"><Icon size={18}/><h3>{title}</h3><p>{desc}</p></div>
          ))}
        </div>
        <div className="welcome-actions">
          <button id="welcome-dashboard-btn" onClick={()=>onNavigate('dashboard')}>
            <BarChart2 size={15}/>{activeCount>0?`Dashboard (${activeCount} running)`:'Open Dashboard'}
          </button>
          <button onClick={()=>onNavigate('chat')}><MessageCircle size={15}/>AI Chat</button>
          <button onClick={()=>onNavigate('settings')}><Lock size={15}/>Settings</button>
          {role==='admin'&&<button onClick={()=>onNavigate('admin')}><Users size={15}/>Admin</button>}
        </div>
      </div>
      <PipelineBlueprint/>
    </section>
  );
}

/* ─── Admin Panel ──────────────────────────────────────────── */
function AdminPanel({ summary, loading }) {
  return (
    <section className="panel admin-panel">
      <div className="section-header"><div><h2>Admin Dashboard</h2><p>Platform-wide overview</p></div>{loading&&<span className="muted" style={{fontSize:12}}>Refreshing…</span>}</div>
      <div className="admin-grid">
        {[['Total Scans',summary?.total_scans??0],['Completed',summary?.completed_scans??0],['Queued / Running',(summary?.queued_scans??0)+(summary?.running_scans??0)],['Users',summary?.user_count??0],['Avg. Score',summary?.average_security_score??0]]
          .map(([label,value])=><div key={label}><span>{label}</span><strong>{value}</strong></div>)}
      </div>
    </section>
  );
}

/* ─── Audit Log ────────────────────────────────────────────── */
function AuditLogPanel({ auditLogs, auditFilters, setAuditFilters }) {
  return (
    <section className="panel audit-panel">
      <div className="section-header"><div><h2>Audit Log</h2><p>Security-relevant platform actions</p></div></div>
      <div className="audit-filter-row">
        {[['action','Action','scan.started'],['targetType','Target Type','scan, user'],['actorEmail','Actor Email','admin@example.com']]
          .map(([key,label,ph])=>(
            <label key={key}>{label}<input type="text" placeholder={ph} value={auditFilters[key]} onChange={e=>setAuditFilters(p=>({...p,[key]:e.target.value}))}/></label>
          ))}
      </div>
      <div className="audit-list">
        {auditLogs.map(log=>(
          <article key={log.id} className="audit-row">
            <div><strong>{log.action}</strong><span>{log.actor_email||log.actor_user_id||'system'}</span></div>
            <div><span>{log.target_type}</span><span>{formatDate(log.created_at)}</span></div>
          </article>
        ))}
        {!auditLogs.length&&<div className="empty-state">No audit events yet.</div>}
      </div>
    </section>
  );
}

/* ─── Users Management ─────────────────────────────────────── */
function UsersManagementPanel({ users, getToken, setNotice, onChanged }) {
  async function changeRole(user, role) {
    try { await apiPatch(`/api/admin/users/${user.id}/role`,{role},getToken); setNotice({type:'success',message:`${user.email||user.id} → ${role}.`}); onChanged(); }
    catch(err) { setNotice({type:'error',message:err.message}); }
  }
  return (
    <section className="panel users-panel">
      <div className="section-header"><div><h2>Users Management</h2><p>Manage local system roles</p></div></div>
      <div className="users-list">
        {users.map(u=>(
          <article key={u.id} className="user-row">
            <div><strong>{u.email||u.id}</strong><span>{u.firstName||u.lastName?`${u.firstName||''} ${u.lastName||''}`.trim():u.id}</span></div>
            <div className="role-control">
              <span className={`role-pill role-${u.role}`}>{u.role}</span>
              <button disabled={u.role==='user'}  onClick={()=>changeRole(u,'user')}>User</button>
              <button disabled={u.role==='admin'} onClick={()=>changeRole(u,'admin')}>Admin</button>
            </div>
          </article>
        ))}
        {!users.length&&<div className="empty-state"><div className="empty-state-icon"><Users size={28}/></div><div className="empty-state-title">No users found</div></div>}
      </div>
    </section>
  );
}

/* ═══════════════════════════════════════════════════════════
   GOOGLE OAUTH BUTTON  — uses Clerk's useSignIn hook
   ═══════════════════════════════════════════════════════════ */
function GoogleSignInButton({ onBusy, setError }) {
  const { signIn, isLoaded } = useSignIn();

  async function handleGoogle() {
    if (!isLoaded) return;
    setError('');
    onBusy(true);
    try {
      await signIn.authenticateWithRedirect({
        strategy:          'oauth_google',
        redirectUrl:       `${window.location.origin}/?sso-callback`,
        redirectUrlComplete: window.location.origin
      });
      /* Page navigates — busy stays true until redirect */
    } catch (err) {
      setError(err?.errors?.[0]?.longMessage || err.message || 'Google sign-in failed.');
      onBusy(false);
    }
  }

  return (
    <button
      type="button"
      className="google-oauth-button"
      onClick={handleGoogle}
      disabled={!isLoaded}
      id="auth-google-btn"
    >
      {/* Official Google "G" SVG */}
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
      </svg>
      Continue with Google
    </button>
  );
}

/* ─── SSO Callback Handler ─────────────────────────────────── */
/**
 * Rendered at /?sso-callback. Completes the Clerk OAuth handshake,
 * then exchanges the Clerk session token for our backend JWT.
 */
function SSOCallbackHandler({ onAuthenticated }) {
  const { session, isLoaded } = useSession();
  const [status, setStatus]   = useState('Completing sign-in…');

  useEffect(() => {
    if (!isLoaded || !session) return;

    async function exchangeToken() {
      setStatus('Verifying your Google account…');
      try {
        const clerkToken = await session.getToken();
        const result     = await submitAuth('/api/auth/clerk', { clerkToken });
        window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(result));
        // Remove the SSO query params from the URL
        const clean = window.location.origin + window.location.pathname;
        window.history.replaceState({}, '', clean);
        onAuthenticated(result);
      } catch (err) {
        setStatus(`Sign-in failed: ${err?.message || 'Unknown error'}`);
      }
    }

    exchangeToken();
  }, [isLoaded, session]);

  return (
    <main className="auth-shell">
      <div className="auth-form-panel" style={{ gridColumn:'1/-1' }}>
        <section className="auth-card" style={{ textAlign:'center' }}>
          <div className="auth-logo"><Shield size={24}/></div>
          <h1>ShieldAI</h1>
          <p style={{ marginTop: 10 }}>{status}</p>
          <div style={{ marginTop: 18 }}>
            <div className="typing-dots" style={{ justifyContent:'center' }}><span/><span/><span/></div>
          </div>
        </section>
      </div>
    </main>
  );
}

/* ─── Sign In Screen ───────────────────────────────────────── */
function SignInScreen({ onAuthenticated }) {
  const [mode,     setMode]    = useState('login');
  const [email,    setEmail]   = useState('');
  const [password, setPassword]= useState('');
  const [error,    setError]   = useState('');
  const [busy,     setBusy]    = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(''); setBusy(true);
    try {
      const path = mode === 'admin'
        ? '/api/auth/admin/login'
        : mode === 'register'
          ? '/api/auth/register'
          : '/api/auth/login';
      const result = await submitAuth(path, { email, password });
      window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(result));
      onAuthenticated(result);
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }

  const brandFeatures = [
    { Icon:Search,   title:'Deep Scan',   desc:'AI-powered static analysis of ZIP repos and GitHub projects.' },
    { Icon:Bot,      title:'AI Guidance', desc:'Chat with an AI that understands your scan context and findings.' },
    { Icon:FileText, title:'PDF Reports', desc:'Professional security reports ready for stakeholders.' },
    { Icon:Lock,     title:'Role-Based',  desc:'Admin and user roles with a full audit trail.' }
  ];

  return (
    <main className="auth-shell">
      {/* ── Left branding panel ── */}
      <div className="auth-brand">
        <div className="auth-brand-logo">
          <div className="auth-brand-logo-icon"><Shield size={24}/></div>
          <span>ShieldAI</span>
        </div>
        <h2>Security reviews powered by <em>artificial intelligence</em></h2>
        <p>Detect vulnerabilities, understand your risk exposure, and ship safer code — faster.</p>
        <div className="auth-features">
          {brandFeatures.map(({Icon,title,desc})=>(
            <div key={title} className="auth-feature">
              <div className="auth-feature-icon"><Icon size={17}/></div>
              <div><strong>{title}</strong><span>{desc}</span></div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Right form panel ── */}
      <div className="auth-form-panel">
        <section className="auth-card">
          <div className="auth-logo"><Shield size={24}/></div>
          <h1>ShieldAI</h1>
          <p>
            {mode==='admin'
              ? 'Admin access is restricted to the configured system administrator.'
              : 'Sign in to your security dashboard or create a new account.'}
          </p>

          {CLERK_PUB_KEY && mode !== 'admin' && (
            <>
              <div className="clerk-form">
                <form
                  className="auth-form"
                  onSubmit={handleSubmit}
                >
                  <div className="auth-field">
                    <div className="auth-label">Email</div>
                    <input
                      id="clerk-identifier"
                      type="text"
                      placeholder="Email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      autoComplete="email"
                    />
                  </div>

                  <div className="auth-field">
                    <div className="auth-label">Password</div>
                    <input
                      id="clerk-password"
                      type="password"
                      placeholder="Password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                    />
                  </div>

                  {error && <div className="auth-error" role="alert">{error}</div>}

                  <div className="auth-underrow">
                    <label className="auth-remember">
                      <input type="checkbox" defaultChecked /> <span>Remember me</span>
                    </label>
                    <a className="auth-link" href="#" onClick={(e)=>e.preventDefault()}>Forgot Password?</a>
                  </div>

                  <button id="auth-submit" className="primary-auth-button" type="submit" disabled={busy}>
                    {busy ? 'Please wait…' : mode === 'register' ? 'Create account' : 'Login'}
                  </button>

                  <div className="auth-divider">
                    <span>or continue with Google</span>
                  </div>

                  <div className="auth-google-row">
                    <GoogleSignInButton onBusy={setBusy} setError={setError}/>
                  </div>

                  <div className="auth-footer">
                    {mode === 'register'
                      ? <>Already have an account? <a href="#" onClick={(e)=>{e.preventDefault(); setMode('login'); setError('');}}>Sign in</a></>
                      : <>Not Registered Yet? <a href="#" onClick={(e)=>{e.preventDefault(); setMode('register'); setError('');}}>Create an account</a></>}
                  </div>
                </form>
              </div>
            </>
          )}

          {/* Admin legacy login remains for admin-only access */}
          {mode === 'admin' && (
            <>
              <div className="auth-tabs" style={{gridTemplateColumns:'1fr'}}>
                {[['admin','Admin']].map(([m,label])=> (
                  <button key={m} className={mode===m?'active':''} onClick={()=>{ setMode(m); setError(''); }}>{label}</button>
                ))}
              </div>
              <form className="auth-form" onSubmit={handleSubmit}>
                <input id="auth-email"    type="email"    placeholder="Admin email" value={email}    onChange={e=>setEmail(e.target.value)}    required/>
                <input id="auth-password" type="password" placeholder="Admin password"      value={password} onChange={e=>setPassword(e.target.value)} required minLength={undefined}/>
                {error && <div className="auth-error" role="alert">{error}</div>}
                <button id="auth-submit" className="primary-auth-button" type="submit" disabled={busy}>
                  {busy?'Please wait…':'Login as Admin'}
                </button>
              </form>
            </>
          )}

          {CLERK_PUB_KEY && mode !== 'admin' && error && <div className="auth-error" role="alert" style={{marginTop:12}}>{error}</div>}

          {/* Hide legacy login/register tabs for non-admin modes */}
          {!CLERK_PUB_KEY && (
            <div className="auth-tabs">
              {[['login','Sign In'],['register','Sign Up'],['admin','Admin']].map(([m,label])=>(
                <button key={m} className={mode===m?'active':''} onClick={()=>{ setMode(m); setError(''); }}>{label}</button>
              ))}
            </div>
          )}

          {!CLERK_PUB_KEY && (
            <form className="auth-form" onSubmit={handleSubmit}>
              <input id="auth-email"    type="email"    placeholder="Email address" value={email}    onChange={e=>setEmail(e.target.value)}    required/>
              <input id="auth-password" type="password" placeholder="Password"      value={password} onChange={e=>setPassword(e.target.value)} required minLength={mode==='register'?8:undefined}/>
              {error && <div className="auth-error" role="alert">{error}</div>}
              <button id="auth-submit" className="primary-auth-button" type="submit" disabled={busy}>
                {busy?'Please wait…': mode==='admin'?'Login as Admin': mode==='register'?'Create Account':'Sign In'}
              </button>
            </form>
          )}
        </section>
      </div>
    </main>
  );
}

/* ─── Dashboard App ────────────────────────────────────────── */
function DashboardApp({ session, onLogout }) {
  const getToken    = useCallback(async()=>session.token,[session.token]);
  const user        = session.user;
  const role        = user?.role==='admin'?'admin':'user';
  const currentUser = { email:user?.email||'Signed-in user', role };

  const [scans,          setScans]         = useState([]);
  const [selectedScanId, setSelectedScanId]= useState(null);
  const [selectedScan,   setSelectedScan]  = useState(null);
  const [adminSummary,   setAdminSummary]  = useState(null);
  const [auditLogs,      setAuditLogs]     = useState([]);
  const [auditFilters,   setAuditFilters]  = useState({action:'',targetType:'',actorEmail:''});
  const [managedUsers,   setManagedUsers]  = useState([]);
  const [settings,       setSettings]      = useState(null);
  const [settingsBusy,   setSettingsBusy]  = useState(false);
  const [chatMessages,   setChatMessages]  = useState([]);
  const [chatInput,      setChatInput]     = useState('');
  const [chatBusy,       setChatBusy]      = useState(false);
  const [chatKey,        setChatKey]       = useState('scanChatHistory:global');
  const [selChatId,      setSelChatId]     = useState(null);
  const [workspace,      setWorkspace]     = useState('welcome');
  const [loading,        setLoading]       = useState(false);
  const [busy,           setBusy]          = useState(false);
  const [notice,         setNotice]        = useState(null);

  useEffect(()=>{ if(!notice)return; const t=setTimeout(()=>setNotice(null),5000); return()=>clearTimeout(t); },[notice]);

  const activeCount = scans.filter(s=>['queued','running'].includes(s.status)).length;

  async function loadScans() {
    setLoading(true);
    try {
      const r = await apiGet('/api/scans',getToken);
      const n = r.scans.map(normalizeScan); setScans(n);
      const still = n.some(s=>s.id===selectedScanId);
      if (!n.length) { setSelectedScanId(null); setSelectedScan(null); }
      else if (!selectedScanId||!still) setSelectedScanId(n[0].id);
    } catch(err) { setNotice({type:'error',message:err.message}); }
    finally { setLoading(false); }
  }

  async function loadScan(id) {
    if (!id) return; setLoading(true);
    try { const r=await apiGet(`/api/scans/${id}`,getToken); setSelectedScan(r.scan); }
    catch(err) { setNotice({type:'error',message:err.message}); }
    finally { setLoading(false); }
  }

  async function loadAdminSummary() { if(role!=='admin')return; try{const r=await apiGet('/api/scans/admin/summary',getToken);setAdminSummary(r.summary);}catch(err){setNotice({type:'error',message:err.message});} }
  async function loadAuditLogs() {
    if(role!=='admin')return;
    try {
      const q=new URLSearchParams(Object.entries(auditFilters).reduce((a,[k,v])=>{if(v?.trim())a[k]=v.trim();return a},{})).toString();
      const r=await apiGet(`/api/admin/audit-logs${q?`?${q}`:''}`,getToken); setAuditLogs(r.auditLogs);
    } catch(err) { setNotice({type:'error',message:err.message}); }
  }
  async function loadManagedUsers() { if(role!=='admin')return; try{const r=await apiGet('/api/admin/users',getToken);setManagedUsers(r.users);}catch(err){setNotice({type:'error',message:err.message});} }
  async function loadAppSettings()  { try{const r=await loadSettings(getToken);setSettings(r.settings);}catch(err){setNotice({type:'error',message:err.message});} }

  function handleScanCreated(id) {
    setSelectedScanId(id); loadScans(); loadScan(id); loadAdminSummary(); loadAuditLogs(); loadManagedUsers();
    setWorkspace('dashboard');
  }

  async function handleSaveSettings() {
    if(!settings)return; setSettingsBusy(true);
    try{const r=await saveSettings(settings,getToken);setSettings(r.settings);setNotice({type:'success',message:'Settings saved.'});}
    catch(err){setNotice({type:'error',message:err.message});}
    finally{setSettingsBusy(false);}
  }

  const resolveChatKey = id => id?`scanChatHistory:${id}`:'scanChatHistory:global';
  useEffect(()=>{
    const key=resolveChatKey(selectedScanId); setChatKey(key);
    try{const s=JSON.parse(localStorage.getItem(key)||'[]');setChatMessages(Array.isArray(s)?s:[]);}catch{setChatMessages([]);}
  },[selectedScanId]);
  useEffect(()=>{ localStorage.setItem(chatKey,JSON.stringify(chatMessages)); },[chatMessages,chatKey]);

  async function handleSendChat() {
    if(!chatInput.trim())return; setChatBusy(true);
    const userMsg={id:`${Date.now()}-${Math.random().toString(36).slice(2,8)}`,role:'user',text:chatInput.trim(),createdAt:new Date().toISOString()};
    setChatMessages(p=>{setSelChatId(userMsg.id);return[...p,userMsg];});
    const payload={question:chatInput.trim()};
    if(selectedScan?.id)payload.scanId=selectedScan.id;
    setChatInput('');
    try {
      const result=await sendChatQuestion(payload,getToken);
      const aiMsg={id:`${Date.now()+1}-${Math.random().toString(36).slice(2,8)}`,role:'assistant',text:result.answer||'No answer returned.',createdAt:new Date().toISOString()};
      setChatMessages(p=>{setSelChatId(aiMsg.id);return[...p,aiMsg];});
    } catch(err) {
      setNotice({type:'error',message:err.message});
      const errMsg={id:`${Date.now()+1}-${Math.random().toString(36).slice(2,8)}`,role:'assistant',text:`Unable to get AI response: ${err.message}`,createdAt:new Date().toISOString()};
      setChatMessages(p=>{setSelChatId(errMsg.id);return[...p,errMsg];});
    } finally{setChatBusy(false);}
  }

  function handleClearChat(){setChatMessages([]);setSelChatId(null);localStorage.removeItem(chatKey);}

  useEffect(()=>{loadScans();loadAdminSummary();loadAuditLogs();loadManagedUsers();loadAppSettings();},[role]);
  useEffect(()=>{if(role==='admin')loadAuditLogs();},[auditFilters,role]);
  useEffect(()=>{loadScan(selectedScanId);},[selectedScanId]);
  useEffect(()=>{
    const active=scans.some(s=>['queued','running'].includes(s.status));
    const selActive=['queued','running'].includes(selectedScan?.status);
    if(!active&&!selActive)return;
    const iv=setInterval(()=>{loadScans();if(selectedScanId)loadScan(selectedScanId);},3000);
    return()=>clearInterval(iv);
  },[scans,selectedScan?.status,selectedScanId]);

  const tabs=[['welcome','Welcome'],['dashboard','Dashboard'],['chat','Chat'],['settings','Settings'],...(role==='admin'?[['admin','Admin']]:[])] ;

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="topbar-brand">
          <div className={`topbar-brand-icon ${activeCount>0?'has-active':''}`}><Shield size={18}/></div>
          <div><strong>ShieldAI Reviewer</strong><span>{currentUser.email} · {role==='admin'?'Administrator':'User'}</span></div>
        </div>
        <nav className="workspace-tabs" role="tablist" aria-label="Workspace">
          {tabs.map(([tab,label])=>(
            <button key={tab} className={workspace===tab?'active':''} onClick={()=>setWorkspace(tab)} role="tab" aria-selected={workspace===tab} id={`tab-${tab}`}>
              {label}
              {tab==='dashboard'&&activeCount>0&&<span style={{marginLeft:5,background:'var(--warning)',color:'var(--bg)',borderRadius:'var(--r-pill)',fontSize:10,fontWeight:800,padding:'1px 5px'}}>{activeCount}</span>}
            </button>
          ))}
        </nav>
        <div className="topbar-actions">
          <button className="logout-button" onClick={onLogout} id="logout-btn"><LogOut size={13}/>Logout</button>
        </div>
      </header>

      {notice&&(
        <div className={`toast ${notice.type}`} role="alert">
          {notice.type==='error'?<AlertTriangle size={14}/>:<CheckCircle2 size={14}/>}
          <span>{notice.message}</span>
          <button onClick={()=>setNotice(null)}>✕</button>
        </div>
      )}

      {workspace==='welcome'&&<div className="workspace-view"><WelcomePanel currentUser={currentUser} role={role} onNavigate={setWorkspace} activeCount={activeCount}/></div>}

      {workspace==='dashboard'&&(
        <div className="workspace-view">
          <UploadPanel onScanCreated={handleScanCreated} busy={busy} setBusy={setBusy} setNotice={setNotice} getToken={getToken} currentUser={currentUser}/>
          <div className="dashboard-context">
            <div><span>Dashboard</span><strong>Scan, Export &amp; Report Workflow</strong></div>
            <p>Queue repositories, view vulnerability reports, and export findings as PDF.</p>
          </div>
          <div className="content-grid">
            <div className="left-stack">
              <ScanHistory scans={scans} selectedScanId={selectedScanId} onSelectScan={setSelectedScanId} onRefresh={loadScans} loading={loading} isAdmin={role==='admin'}/>
            </div>
            <ReportPanel scan={selectedScan} loading={loading} getToken={getToken} setNotice={setNotice} onExported={loadAuditLogs}/>
          </div>
        </div>
      )}

      {workspace==='chat'&&(
        <div className="workspace-view chat-workspace">
          <ConversationHistorySidebar chatMessages={chatMessages} selectedMessageId={selChatId} onSelectMessage={setSelChatId} onNewChat={handleClearChat}/>
          <div className="chat-main">
            <ChatPanel selectedScan={selectedScan} chatMessages={chatMessages} draft={chatInput} setDraft={setChatInput} onSend={handleSendChat} onClear={handleClearChat} chatBusy={chatBusy}/>
          </div>
        </div>
      )}

      {workspace==='settings'&&<div className="workspace-view"><SettingsPanel currentUser={currentUser} settings={settings} busy={settingsBusy} onSave={handleSaveSettings} setSettings={setSettings}/></div>}

      {workspace==='admin'&&role==='admin'&&(
        <div className="workspace-view admin-dashboard-grid">
          <AdminPanel summary={adminSummary} loading={loading}/>
          <UsersManagementPanel users={managedUsers} getToken={getToken} setNotice={setNotice} onChanged={()=>{loadManagedUsers();loadAuditLogs();}}/>
          <AuditLogPanel auditLogs={auditLogs} auditFilters={auditFilters} setAuditFilters={setAuditFilters}/>
        </div>
      )}
    </main>
  );
}

/* ─── Root App ─────────────────────────────────────────────── */
function App() {
  const [session, setSession] = useState(()=>{
    const s=window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    return s?JSON.parse(s):null;
  });

  function handleLogout(){ window.sessionStorage.removeItem(SESSION_STORAGE_KEY); setSession(null); }

  // Detect SSO callback redirect from Clerk Google OAuth
  const isSSOCallback = window.location.search.includes('sso-callback') ||
                        window.location.search.includes('__clerk_status');

  if (isSSOCallback) {
    return <AuthenticateWithRedirectCallback afterSignInUrl="/" afterSignUpUrl="/"/>;
  }

  if (!session) return <SignInScreen onAuthenticated={setSession}/>;
  return <DashboardApp session={session} onLogout={handleLogout}/>;
}

/* ─── Entry Point ──────────────────────────────────────────── */
const container = document.getElementById('root');

if (CLERK_PUB_KEY) {
  createRoot(container).render(
    <ClerkProvider publishableKey={CLERK_PUB_KEY} afterSignInUrl="/" afterSignUpUrl="/">
      <AppWithClerkExchange/>
    </ClerkProvider>
  );
} else {
  createRoot(container).render(<App/>);
}

/**
 * When Clerk is available, this wrapper checks if we have an active Clerk session
 * after a Google OAuth redirect and auto-exchanges it for our backend JWT.
 */
function AppWithClerkExchange() {
  const { session, isLoaded } = useSession();
  const [appSession, setAppSession] = useState(()=>{
    const s=window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    return s?JSON.parse(s):null;
  });
  const [exchanging, setExchanging] = useState(false);

  function handleLogout(){ window.sessionStorage.removeItem(SESSION_STORAGE_KEY); setAppSession(null); }

  const isSSOCallback = window.location.search.includes('sso-callback') ||
                        window.location.search.includes('__clerk_status');

  // After Clerk Google OAuth redirect, complete the handshake
  useEffect(()=>{
    if (!isLoaded || !session || appSession || exchanging || !isSSOCallback) return;
    setExchanging(true);

    async function exchange() {
      try {
        const clerkToken = await session.getToken();
        const result     = await submitAuth('/api/auth/clerk', { clerkToken });
        window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(result));
        const clean = window.location.origin + window.location.pathname;
        window.history.replaceState({}, '', clean);
        setAppSession(result);
      } catch(err) {
        console.error('Clerk token exchange failed:', err);
        setExchanging(false);
      }
    }
    exchange();
  }, [isLoaded, session, appSession, exchanging, isSSOCallback]);

  if (isSSOCallback) {
    return (
      <>
        <AuthenticateWithRedirectCallback afterSignInUrl="/" afterSignUpUrl="/"/>
        <SSOCallbackHandler onAuthenticated={setAppSession}/>
      </>
    );
  }

  if (!appSession) return <SignInScreen onAuthenticated={setAppSession}/>;
  return <DashboardApp session={appSession} onLogout={handleLogout}/>;
}

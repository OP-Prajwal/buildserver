'use strict';

// Read backend URL from config.js (set BACKEND_URL to your Render URL when deploying to Vercel)
const _cfg = window.ATTESTGATE_CONFIG || {};
const BACKEND_HTTP = _cfg.BACKEND_URL || `${location.protocol}//${location.host}`;
const WS_URL = BACKEND_HTTP.replace('https://', 'wss://').replace('http://', 'ws://');

// All API calls go through this helper so they always hit the right backend
function api(path, opts) {
  return fetch(BACKEND_HTTP + path, opts);
}

let ws, reconnectTimer;

// Tab switcher
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  
  const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick')?.includes(tabId));
  if (activeBtn) activeBtn.classList.add('active');
  
  const content = document.getElementById(`tab-${tabId}`);
  if (content) content.classList.add('active');
}
window.switchTab = switchTab;

function connect() {
  ws = new WebSocket(WS_URL);
  ws.addEventListener('open', () => { setWsStatus('connected', 'Live'); clearTimeout(reconnectTimer); });
  ws.addEventListener('close', () => { setWsStatus('error', 'Reconnecting...'); reconnectTimer = setTimeout(connect, 3000); });
  ws.addEventListener('error', () => setWsStatus('error', 'Connection error'));
  ws.addEventListener('message', evt => { try { handleMessage(JSON.parse(evt.data)); } catch(e) {} });
}

function handleMessage({ event, data }) {
  switch (event) {
    case 'init':                  onInit(data);                break;
    case 'log':                   appendLog(data);             break;
    case 'deployment:started':    onDeploymentStarted(data);   break;
    case 'deployment:step':       onDeploymentStep(data);      break;
    case 'deployment:deployed':   onDeploymentDeployed(data);  break;
    case 'deployment:rejected':   onDeploymentRejected(data);  break;
    case 'deployment:failed':     onDeploymentFailed(data);    break;
    case 'team:updated':          renderTeam(data);            break;
    case 'prs:updated':           renderPRs(data);             break;
    case 'invitations:updated':   renderInvitations(data);     break;
  }
}

function onInit(data) {
  if (data.deployments?.length) {
    data.deployments.forEach(d => addHistoryItem(d));
    const latest = data.deployments[0];
    renderActiveDeployment(latest);
    if (latest.status === 'deployed') {
      renderChecksFromRecord(latest);
      showVerdict('approved', `✅ DEPLOYED — ${latest.image}`);
      setPipelineStage('deploy', 'passed');
    } else if (latest.status === 'rejected') {
      renderChecksFromRecord(latest);
      showVerdict('rejected', `🚨 REJECTED — ${rejectedReasonLabel(latest.rejectedReason)}`);
    }
  }
}

function onDeploymentStarted(dep) {
  renderActiveDeployment(dep);
  addHistoryItem(dep);
  resetChecks(dep.mode);
  clearVerdict();
  setPipelineStage('gate', 'running');
  setPipelineStage('deploy', null);
  setPipelineStage('source', 'passed');
  setPipelineStage('ci', 'passed');
  setPipelineStage('registry', 'passed');
  updateCheck('webhook', 'passed', 'Passed');

  // Update Hash Gate
  const ciEl = document.getElementById('ciHashVal');
  const targetEl = document.getElementById('targetHashVal');
  const statusEl = document.getElementById('hashGateStatus');
  const resEl = document.getElementById('hashCompareResult');
  if (ciEl) ciEl.textContent = dep.digest ? dep.digest.slice(0, 24) + '...' : 'pending...';
  if (targetEl) targetEl.textContent = 'Inspecting Docker/K8s digest...';
  if (statusEl) { statusEl.className = 'check-badge checking'; statusEl.textContent = 'Comparing Hashes...'; }
  if (resEl) resEl.style.display = 'none';
}

function onDeploymentStep({ id, step, status, packageCount }) {
  updateCheck(step, status, stepLabel(step, status, { packageCount }));
  if (status === 'checking' || status === 'running') setPipelineStage('gate', 'running');
}

function onDeploymentDeployed(dep) {
  updateHistoryItem(dep);
  renderActiveDeployment(dep);
  updateCheck('deploy', 'passed', 'Running');
  setPipelineStage('gate', 'passed');
  setPipelineStage('deploy', 'passed');
  showVerdict('approved', `✅ DEPLOYMENT APPROVED — ${dep.image}`);

  // Hash match confirmed
  const targetEl = document.getElementById('targetHashVal');
  const statusEl = document.getElementById('hashGateStatus');
  const resEl = document.getElementById('hashCompareResult');
  if (targetEl) targetEl.textContent = dep.digest ? dep.digest.slice(0, 24) + '...' : 'verified';
  if (statusEl) { statusEl.className = 'check-badge passed'; statusEl.textContent = 'HASH MATCH ✅'; }
  if (resEl) {
    resEl.style.display = 'block';
    resEl.style.background = 'rgba(34, 197, 94, 0.15)';
    resEl.style.color = '#4ade80';
    resEl.style.border = '1px solid #22c55e';
    resEl.textContent = '✅ CI Hash == Target Hash. Cryptographic Provenance Confirmed. Pod deployed.';
  }
}

function onDeploymentRejected(dep) {
  updateHistoryItem(dep);
  renderActiveDeployment(dep);
  renderChecksFromRecord(dep);
  setPipelineStage('gate', 'failed');
  setPipelineStage('deploy', null);
  showVerdict('rejected', `🚨 DEPLOYMENT REJECTED — ${rejectedReasonLabel(dep.rejectedReason)}`);

  // Hash mismatch / tampering caught
  const targetEl = document.getElementById('targetHashVal');
  const statusEl = document.getElementById('hashGateStatus');
  const resEl = document.getElementById('hashCompareResult');
  if (targetEl) targetEl.textContent = 'sha256:99badf00d817... (TAMPERED)';
  if (statusEl) { statusEl.className = 'check-badge failed'; statusEl.textContent = 'MISMATCH DETECTED ❌'; }
  if (resEl) {
    resEl.style.display = 'block';
    resEl.style.background = 'rgba(239, 68, 68, 0.15)';
    resEl.style.color = '#f87171';
    resEl.style.border = '1px solid #ef4444';
    resEl.textContent = '🚨 CANCELLED DEPLOYMENT: Docker/K8s image hash does NOT match signed CI commit!';
  }
}

function onDeploymentFailed(dep) {
  updateHistoryItem(dep);
  setPipelineStage('gate', 'failed');
  showVerdict('rejected', `❌ DEPLOYMENT FAILED`);
}


// Logs
const logFeed = document.getElementById('logFeed');
function appendLog({ level, message }) {
  if (!logFeed) return;
  const line = document.createElement('div');
  line.className = `log-line ${level}`;
  const ts = document.createElement('span');
  ts.className = 'log-ts';
  ts.textContent = new Date().toTimeString().slice(0, 8);
  const msg = document.createElement('span');
  msg.className = 'log-msg';
  msg.textContent = message;
  line.append(ts, msg);
  logFeed.appendChild(line);
  logFeed.scrollTop = logFeed.scrollHeight;
  while (logFeed.children.length > 500) logFeed.removeChild(logFeed.firstChild);
}
function clearLogs() { if (logFeed) logFeed.innerHTML = ''; }
window.clearLogs = clearLogs;

// Active deployment
const activeEl = document.getElementById('activeDeployment');
function renderActiveDeployment(dep) {
  if (!activeEl) return;
  activeEl.innerHTML = '';
  activeEl.className = 'deployment-card';
  const rows = [
    ['Image', dep.image],
    ['Digest', dep.digest ? dep.digest.slice(0, 32) + '...' : '—'],
    ['Commit', dep.sha?.slice(0, 7) || '—'],
    ['Ref', dep.ref || '—'],
    ['Workflow', dep.workflow || '—'],
    ['Mode', dep.mode],
    ['Status', dep.status]
  ];
  for (const [label, value] of rows) {
    const row = document.createElement('div');
    row.className = 'dep-row';
    const lbl = document.createElement('span');
    lbl.className = 'dep-label';
    lbl.textContent = label;
    const val = document.createElement('span');
    val.className = 'dep-value';
    val.textContent = value;
    row.append(lbl, val);
    activeEl.appendChild(row);
  }
}

// Checks
function resetChecks(mode) {
  for (const key of ['webhook', 'signature', 'sbom', 'pull', 'digest', 'deploy']) {
    updateCheck(key, 'idle', '—');
  }
}
function updateCheck(step, status, label) {
  const item = document.getElementById(`check-${step}`);
  const badge = document.getElementById(`badge-${step}`);
  if (!item || !badge) return;
  item.className = `check-item ${status}`;
  badge.className = `check-badge ${status}`;
  badge.textContent = label || status;
}
function renderChecksFromRecord(dep) {
  if (!dep.checks) return;
  for (const [step, status] of Object.entries(dep.checks)) {
    if (status) updateCheck(step, status, status === 'passed' ? 'Passed' : 'Failed');
  }
}
function stepLabel(step, status, { packageCount } = {}) {
  if (status === 'checking' || status === 'running') return 'Checking...';
  if (status === 'passed') {
    if (step === 'sbom' && packageCount) return `${packageCount} pkgs`;
    return 'Passed';
  }
  return status === 'failed' ? 'Failed' : '—';
}

// Verdict
const verdictEl = document.getElementById('verdictBanner');
function showVerdict(type, message) {
  if (!verdictEl) return;
  verdictEl.className = `verdict-banner ${type}`;
  verdictEl.textContent = message;
}
function clearVerdict() {
  if (!verdictEl) return;
  verdictEl.className = 'verdict-banner hidden';
  verdictEl.textContent = '';
}

// Pipeline
function setPipelineStage(stage, state) {
  const el = document.getElementById(`stage-${stage}`);
  if (!el) return;
  el.className = ['pipeline-stage', state, stage === 'gate' ? 'active' : ''].filter(Boolean).join(' ');
}

// History
const historyList = document.getElementById('historyList');
function addHistoryItem(dep) {
  if (!historyList) return;
  const empty = historyList.querySelector('.empty-state');
  if (empty) empty.remove();
  if (document.getElementById(`hist-${dep.id}`)) return;
  historyList.prepend(buildHistoryItem(dep));
}
function updateHistoryItem(dep) {
  const el = document.getElementById(`hist-${dep.id}`);
  if (el) el.replaceWith(buildHistoryItem(dep));
}
function buildHistoryItem(dep) {
  const item = document.createElement('div');
  item.className = 'history-item';
  item.id = `hist-${dep.id}`;
  const dot = document.createElement('div');
  dot.className = `history-dot ${dep.status}`;
  const main = document.createElement('div');
  main.className = 'history-main';
  const img = document.createElement('div');
  img.className = 'history-image';
  img.textContent = dep.image;
  const meta = document.createElement('div');
  meta.className = 'history-meta';
  meta.textContent = `${new Date(dep.startedAt).toLocaleTimeString()} · ${dep.sha?.slice(0, 7) || '—'}`;
  main.append(img, meta);
  const status = document.createElement('div');
  status.className = 'history-status';
  status.textContent = dep.status;
  item.append(dot, main, status);
  return item;
}

// Team rendering
function renderTeam(team) {
  const list = document.getElementById('teamList');
  const select = document.getElementById('prAuthorSelect');
  if (list && team) {
    list.innerHTML = '';
    team.forEach(m => {
      const el = document.createElement('div');
      el.className = 'team-item';
      el.innerHTML = `
        <div>
          <div class="team-name">${m.name}</div>
          <div class="team-github">@${m.github} &nbsp;·&nbsp; <span style="font-size: 0.72rem; color: var(--text-muted);">${m.email || 'linked'}</span></div>
        </div>
        <div class="team-role">${m.role}</div>
      `;
      list.appendChild(el);
    });
  }

  if (select && team) {
    select.innerHTML = '';
    team.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m.github;
      opt.textContent = `${m.name} (@${m.github}) — ${m.role}`;
      select.appendChild(opt);
    });
  }
}

async function addTeamMember(e) {
  e.preventDefault();
  const name = document.getElementById('devName').value.trim();
  const github = document.getElementById('devGithub').value.trim();
  const role = document.getElementById('devRole').value;
  if (!name || !github) return;

  await api('/api/team', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, github, role })
  });

  document.getElementById('devName').value = '';
  document.getElementById('devGithub').value = '';
  loadStatus();
}
window.addTeamMember = addTeamMember;

// PR rendering
function renderPRs(prs) {
  const list = document.getElementById('prList');
  if (!list || !prs) return;
  list.innerHTML = '';
  prs.forEach(pr => {
    const el = document.createElement('div');
    el.className = 'pr-item';
    el.innerHTML = `
      <div class="pr-main">
        <span class="pr-badge">PR #${pr.id}</span>
        <div>
          <div class="pr-title">${pr.title}</div>
          <div class="pr-meta">
            Author: <strong>@${pr.author}</strong> (${pr.authorName || 'Dev'}) · 
            Commit: <code>${pr.commit}</code> · 
            <a href="${pr.url || '#'}" target="_blank" style="color: var(--accent); text-decoration: none;">View PR ↗</a>
          </div>
        </div>
      </div>
      <div>
        <span class="attested-tag">${pr.attested ? '✅ Hash Verified & Attested' : 'Pending'}</span>
      </div>
    `;
    list.appendChild(el);
  });
}

async function submitOfficialPR(e) {
  e.preventDefault();
  const author = document.getElementById('prAuthorSelect').value;
  const url = document.getElementById('prUrlInput').value.trim();
  const title = document.getElementById('prTitleInput').value.trim();
  if (!url || !title) return;

  const btn = e.target.querySelector('button[type=submit]');
  btn.textContent = 'Attesting PR & Generating Cryptographic Hash...';
  btn.disabled = true;

  const res = await api('/api/prs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title, author, url })
  });
  const data = await res.json();

  btn.textContent = '🔗 Attest Official PR Provenance';
  btn.disabled = false;
  document.getElementById('prUrlInput').value = '';
  document.getElementById('prTitleInput').value = '';

  if (data.success) {
    appendLog({ level: 'success', message: `🔗 PR #${data.pr.id} successfully attested by @${data.pr.author}. Deployment permission granted!` });
    await loadStatus();
  }
}
window.submitOfficialPR = submitOfficialPR;


// Simulations
async function triggerCleanDeploy() {
  switchTab('gate');
  appendLog({ level: 'info', message: 'Triggering approved PR #14 deployment through AttestGate...' });
  await api('/api/simulate/clean', { method: 'POST' });
}
window.triggerCleanDeploy = triggerCleanDeploy;

async function triggerAttackDeploy() {
  switchTab('gate');
  appendLog({ level: 'attack', message: '⚠️ Incoming malicious deployment attempt (unauthorized container hash)...' });
  await api('/api/simulate/attack', { method: 'POST' });
}
window.triggerAttackDeploy = triggerAttackDeploy;

// Helpers
function setWsStatus(state, label) {
  const el = document.getElementById('wsIndicator');
  if (!el) return;
  el.querySelector('.ws-label').textContent = label;
  el.className = `ws-indicator ${state}`;
}
function rejectedReasonLabel(reason) {
  return {
    signature_failed: 'Cosign signature invalid — image untrusted',
    sbom_failed: 'SBOM attestation missing',
    digest_mismatch: 'SHA-256 digest tampered'
  }[reason] || reason || 'Gatekeeper policy rejection';
}

// Invitations
function renderInvitations(invitations) {
  const list = document.getElementById('invitationList');
  if (!list || !invitations) return;
  list.innerHTML = '';
  if (!invitations.length) {
    list.innerHTML = '<div class="empty-state"><span class="empty-icon">📮</span><span>No pending invitations</span></div>';
    return;
  }
  invitations.forEach(inv => {
    const el = document.createElement('div');
    el.className = 'invitation-item';
    const isPending = inv.status === 'Pending';
    el.innerHTML = `
      <div class="inv-main">
        <div class="inv-name">${inv.name} — <span style="color: var(--text-muted); font-size: 0.78rem;">${inv.email}</span></div>
        <div class="inv-meta">Role: ${inv.role} &nbsp;·&nbsp; Join Code: <span class="inv-code">${inv.code}</span></div>
      </div>
      <div class="inv-actions">
        ${isPending
          ? `<button class="btn-accept" onclick="acceptInvitation('${inv.code}')">✅ Accept Join</button>`
          : `<span class="inv-accepted">✅ Accepted</span>`
        }
      </div>
    `;
    list.appendChild(el);
  });
}
window.renderInvitations = renderInvitations;

async function sendInvitation(e) {
  e.preventDefault();
  const name   = document.getElementById('invName').value.trim();
  const email  = document.getElementById('invEmail').value.trim();
  const github = document.getElementById('invGithub').value.trim();
  const role   = document.getElementById('invRole').value;
  if (!name || !email) return;

  const btn = e.target.querySelector('button[type=submit]');
  btn.textContent = 'Sending...';
  btn.disabled = true;

  await api('/api/invitations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, github, role })
  });

  btn.textContent = '✉️ Send Email Invitation';
  btn.disabled = false;
  document.getElementById('invName').value = '';
  document.getElementById('invEmail').value = '';
  document.getElementById('invGithub').value = '';
  await loadStatus();
}
window.sendInvitation = sendInvitation;

async function acceptInvitation(code) {
  const res = await api('/api/invitations/accept', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code })
  });
  const data = await res.json();
  if (data.success) {
    appendLog({ level: 'success', message: `🎉 ${data.member.name} (@${data.member.github}) joined workspace with role: ${data.member.role}` });
    await loadStatus();
  }
}
window.acceptInvitation = acceptInvitation;

async function loadStatus() {
  try {
    const data = await api('/api/status').then(r => r.json());
    if (data.team)        renderTeam(data.team);
    if (data.prs)         renderPRs(data.prs);
    if (data.invitations) renderInvitations(data.invitations);
    if (data.deployments?.length) onInit({ deployments: data.deployments });
  } catch {}
}

async function init() {
  await loadStatus();
  connect();
}
init();


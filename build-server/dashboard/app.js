'use strict';

const WS_URL = `ws://${location.host}`;
let ws, reconnectTimer;

function connect() {
  ws = new WebSocket(WS_URL);
  ws.addEventListener('open', () => { setWsStatus('connected', 'Live'); clearTimeout(reconnectTimer); });
  ws.addEventListener('close', () => { setWsStatus('error', 'Disconnected — reconnecting...'); reconnectTimer = setTimeout(connect, 3000); });
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
  }
}

function onInit({ deployments }) {
  if (!deployments?.length) return;
  deployments.forEach(d => addHistoryItem(d));
  const latest = deployments[0];
  renderActiveDeployment(latest);
  if (latest.status === 'deployed') { renderChecksFromRecord(latest); showVerdict('approved', `✅ DEPLOYED — ${latest.image}`); setPipelineStage('deploy', 'passed'); }
  else if (latest.status === 'rejected') { renderChecksFromRecord(latest); showVerdict('rejected', `🚨 REJECTED — ${rejectedReasonLabel(latest.rejectedReason)}`); }
}

function onDeploymentStarted(dep) {
  renderActiveDeployment(dep); addHistoryItem(dep); resetChecks(dep.mode); clearVerdict();
  setPipelineStage('gate', 'running'); setPipelineStage('deploy', null);
  setPipelineStage('source', 'passed'); setPipelineStage('ci', 'passed'); setPipelineStage('registry', 'passed');
  updateCheck('webhook', 'passed', 'Passed');
}

function onDeploymentStep({ id, step, status, packageCount }) {
  updateCheck(step, status, stepLabel(step, status, { packageCount }));
  if (status === 'checking' || status === 'running') setPipelineStage('gate', 'running');
}

function onDeploymentDeployed(dep) {
  updateHistoryItem(dep); renderActiveDeployment(dep); updateCheck('deploy', 'passed', 'Running');
  setPipelineStage('gate', 'passed'); setPipelineStage('deploy', 'passed');
  showVerdict('approved', `✅ DEPLOYMENT APPROVED — ${dep.image}`);
}

function onDeploymentRejected(dep) {
  updateHistoryItem(dep); renderActiveDeployment(dep); renderChecksFromRecord(dep);
  setPipelineStage('gate', 'failed'); setPipelineStage('deploy', null);
  showVerdict('rejected', `🚨 DEPLOYMENT REJECTED — ${rejectedReasonLabel(dep.rejectedReason)}`);
}

function onDeploymentFailed(dep) { updateHistoryItem(dep); setPipelineStage('gate', 'failed'); showVerdict('rejected', `❌ DEPLOYMENT FAILED`); }

// Logs
const logFeed = document.getElementById('logFeed');
function appendLog({ level, message }) {
  const line = document.createElement('div'); line.className = `log-line ${level}`;
  const ts = document.createElement('span'); ts.className = 'log-ts'; ts.textContent = new Date().toTimeString().slice(0,8);
  const msg = document.createElement('span'); msg.className = 'log-msg'; msg.textContent = message;
  line.append(ts, msg); logFeed.appendChild(line); logFeed.scrollTop = logFeed.scrollHeight;
  while (logFeed.children.length > 500) logFeed.removeChild(logFeed.firstChild);
}
function clearLogs() { logFeed.innerHTML = ''; }
window.clearLogs = clearLogs;

// Active deployment
const activeEl = document.getElementById('activeDeployment');
function renderActiveDeployment(dep) {
  activeEl.innerHTML = ''; activeEl.className = 'deployment-card';
  const rows = [['Image', dep.image], ['Digest', dep.digest ? dep.digest.slice(0,32)+'...' : '—'], ['Commit', dep.sha?.slice(0,7) || '—'], ['Ref', dep.ref || '—'], ['Workflow', dep.workflow || '—'], ['Mode', null], ['Status', dep.status]];
  for (const [label, value] of rows) {
    const row = document.createElement('div'); row.className = 'dep-row';
    const lbl = document.createElement('span'); lbl.className = 'dep-label'; lbl.textContent = label;
    if (label === 'Mode') { const badge = document.createElement('span'); badge.className = `mode-badge ${dep.mode}`; badge.textContent = dep.mode; row.append(lbl, badge); }
    else { const val = document.createElement('span'); val.className = 'dep-value'; val.textContent = value; row.append(lbl, val); }
    activeEl.appendChild(row);
  }
}

// Checks
function resetChecks(mode) {
  for (const key of ['webhook','signature','sbom','pull','digest','deploy']) {
    const relevant = mode === 'protected' || key === 'webhook' || key === 'pull' || key === 'deploy';
    updateCheck(key, relevant ? 'idle' : 'skipped', relevant ? '—' : 'Skipped');
  }
}
function updateCheck(step, status, label) {
  const item = document.getElementById(`check-${step}`); const badge = document.getElementById(`badge-${step}`);
  if (!item || !badge) return;
  item.className = `check-item ${status}`; badge.className = `check-badge ${status}`; badge.textContent = label || status;
}
function renderChecksFromRecord(dep) {
  if (!dep.checks) return;
  const map = { webhook: dep.checks.webhook, signature: dep.checks.signature, sbom: dep.checks.sbom, digest: dep.checks.digest, deploy: dep.status === 'deployed' ? 'passed' : null };
  for (const [step, status] of Object.entries(map)) if (status) updateCheck(step, status, status === 'passed' ? 'Passed' : 'Failed');
}
function stepLabel(step, status, { packageCount } = {}) {
  if (status === 'checking' || status === 'running') return status === 'running' ? 'Running...' : 'Checking...';
  if (status === 'passed') { if (step === 'sbom' && packageCount) return `${packageCount} pkgs`; return 'Passed'; }
  return status === 'failed' ? 'Failed' : '—';
}

// Verdict
const verdictEl = document.getElementById('verdictBanner');
function showVerdict(type, message) { verdictEl.className = `verdict-banner ${type}`; verdictEl.textContent = message; }
function clearVerdict() { verdictEl.className = 'verdict-banner hidden'; verdictEl.textContent = ''; }

// Pipeline
function setPipelineStage(stage, state) {
  const el = document.getElementById(`stage-${stage}`);
  if (!el) return;
  el.className = ['pipeline-stage', state, stage === 'gate' ? 'active' : ''].filter(Boolean).join(' ');
}

// History
const historyList = document.getElementById('historyList');
function addHistoryItem(dep) {
  const empty = historyList.querySelector('.empty-state'); if (empty) empty.remove();
  if (document.getElementById(`hist-${dep.id}`)) return;
  historyList.prepend(buildHistoryItem(dep));
}
function updateHistoryItem(dep) { const el = document.getElementById(`hist-${dep.id}`); if (el) el.replaceWith(buildHistoryItem(dep)); }
function buildHistoryItem(dep) {
  const item = document.createElement('div'); item.className = 'history-item'; item.id = `hist-${dep.id}`;
  const dot = document.createElement('div'); dot.className = `history-dot ${dep.status}`;
  const main = document.createElement('div'); main.className = 'history-main';
  const img = document.createElement('div'); img.className = 'history-image'; img.textContent = dep.image;
  const meta = document.createElement('div'); meta.className = 'history-meta';
  meta.textContent = `${new Date(dep.startedAt).toLocaleTimeString()} · ${dep.mode} · ${dep.sha?.slice(0,7) || '—'}`;
  main.append(img, meta);
  const status = document.createElement('div'); status.className = `history-status ${dep.status}`; status.textContent = dep.status;
  item.append(dot, main, status); return item;
}

// Helpers
function setWsStatus(state, label) { const el = document.getElementById('wsIndicator'); el.querySelector('.ws-label').textContent = label; el.className = `ws-indicator ${state}`; }
function rejectedReasonLabel(reason) { return { signature_failed:'Invalid image signature', sbom_failed:'SBOM attestation invalid', pull_failed:'Docker pull failed', digest_mismatch:'Digest mismatch — image tampered!' }[reason] || reason || 'Unknown'; }

async function init() {
  try {
    const data = await fetch('/api/status').then(r => r.json());
    const badge = document.getElementById('cosignBadge');
    if (data.cosign) { badge.textContent = 'cosign: ✓ installed'; badge.className = 'cosign-badge ok'; }
    else { badge.textContent = 'cosign: ✗ missing'; badge.className = 'cosign-badge err'; }
    if (data.deployments?.length) onInit({ deployments: data.deployments });
  } catch {}
  connect();
}
init();

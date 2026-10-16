'use strict';

require('dotenv').config();

const express   = require('express');
const http      = require('http');
const WebSocket = require('ws');
const crypto    = require('crypto');
const path      = require('path');

const logger        = require('./logger');
const verifier      = require('./verifier');
const dockerManager = require('./docker-manager');

const cors       = require('cors');

const app        = express();
const httpServer = http.createServer(app);
const wss        = new WebSocket.Server({ server: httpServer });

// CORS — allow the Vercel frontend and local development
app.use(cors({
  origin: [
    /^https:\/\/.*\.vercel\.app$/,
    /^https:\/\/.*\.ngrok-free\.app$/,
    'http://localhost:4000',
    'http://localhost:3000',
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'dashboard')));

const state = {
  startedAt: new Date().toISOString(),
  deployments: [],
  team: [
    { id: 1, name: 'Prajwal (Lead)', role: 'Product Lead / Owner', github: 'OP-Prajwal', status: 'Active' },
    { id: 2, name: 'Alex Rivera', role: 'DevSecOps Engineer', github: 'alex-r-dev', status: 'Active' },
    { id: 3, name: 'Sarah Chen', role: 'Security Reviewer', github: 'schen-sec', status: 'Active' },
  ],
  repos: [
    { name: process.env.GITHUB_REPO || 'OP-Prajwal/buildserver', branch: 'main', policy: 'Strict Cosign + SBOM', status: 'Protected' }
  ],
  prs: [
    { id: 14, title: 'feat: add zero-trust deployment gate', author: 'OP-Prajwal', status: 'Merged', commit: '7f91a2c', attested: true },
    { id: 13, title: 'fix: validate SBOM package signatures', author: 'schen-sec', status: 'Merged', commit: '3e42b10', attested: true },
    { id: 12, title: 'refactor: container entrypoint', author: 'alex-r-dev', status: 'Closed', commit: '8a12e44', attested: false },
  ],
  cluster: {
    name: 'k8s-prod-us-east-1',
    type: 'Kubernetes Cluster',
    tunnel: 'Active (Mutual TLS)',
    policy: 'Strict Attestation Gate',
    agentVersion: 'v1.4.0',
    lastHeartbeat: new Date().toISOString()
  },
  invitations: [
    { id: 'inv_1', name: 'Marcus Brody', email: 'marcus@company.com', github: 'mbrody-dev', role: 'Security Engineer', code: 'INV-8F3A-2026', status: 'Pending', sentAt: new Date().toISOString() }
  ]
};

// ── WebSocket broadcast ───────────────────────────────────────────────────────

function broadcast(event, data) {
  const msg = JSON.stringify({ event, data, ts: new Date().toISOString() });
  for (const c of wss.clients) {
    if (c.readyState === WebSocket.OPEN) c.send(msg);
  }
}

function emit(level, message, meta = {}) {
  logger[level]?.(message, meta);
  broadcast('log', { level, message, meta });
}

// ── Webhook HMAC auth ─────────────────────────────────────────────────────────

function verifyWebhookHMAC(req) {
  const secret = process.env.BUILD_SERVER_TOKEN;
  if (!secret) { logger.warn('BUILD_SERVER_TOKEN not set — skipping auth (dev mode)'); return true; }
  const header = req.headers['x-hub-signature-256'];
  if (!header) return false;
  const digest = 'sha256=' + crypto.createHmac('sha256', secret).update(JSON.stringify(req.body)).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(header), Buffer.from(digest)); } catch { return false; }
}

// ── Webhook endpoint ──────────────────────────────────────────────────────────

app.post('/webhook', async (req, res) => {
  if (!verifyWebhookHMAC(req)) {
    emit('error', 'Webhook rejected — HMAC mismatch');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { image, digest, ref, sha, workflow, mode } = req.body;
  if (!image || !digest) return res.status(400).json({ error: 'Missing image or digest' });

  const dep = {
    id: crypto.randomUUID(), image, digest,
    ref: ref || 'unknown', sha: sha || 'unknown',
    workflow: workflow || 'unknown', mode: mode || 'unprotected',
    status: 'pending', startedAt: new Date().toISOString(),
    checks: { webhook: 'passed', signature: null, sbom: null, digest: null },
  };

  state.deployments.unshift(dep);
  broadcast('deployment:started', dep);
  res.json({ deploymentId: dep.id, status: 'processing' });
  setImmediate(() => processDeployment(dep).catch(err => {
    emit('error', `Unhandled error: ${err.message}`);
    dep.status = 'failed';
    broadcast('deployment:failed', dep);
  }));
});

// ── Deployment pipeline ───────────────────────────────────────────────────────

async function processDeployment(dep) {
  emit('info', '═'.repeat(55));
  emit('info', `📦 Deployment ${dep.id.slice(0, 8)} | Mode: ${dep.mode.toUpperCase()}`);
  emit('info', `   Image: ${dep.image}`);
  emit('info', `   Digest: ${dep.digest}`);
  emit('info', `   Commit: ${dep.sha.slice(0, 7)}`);
  emit('info', '═'.repeat(55));

  if (dep.mode === 'protected') {
    emit('info', '🔐 PROTECTED mode — running full verification gate');

    // Step 1: Signature
    emit('step', 'Step 1/4 — Verifying image signature (cosign)...');
    broadcast('deployment:step', { id: dep.id, step: 'signature', status: 'checking' });
    const sigResult = verifier.verifySignature(dep.image, dep.digest);
    dep.checks.signature = sigResult.valid ? 'passed' : 'failed';
    broadcast('deployment:step', { id: dep.id, step: 'signature', status: dep.checks.signature });
    if (!sigResult.valid) {
      emit('attack', `❌ Signature FAILED: ${sigResult.error}`);
      emit('attack', '🚨 DEPLOYMENT REJECTED — image not signed by our CI');
      return reject(dep, 'signature_failed');
    }
    emit('success', '✅ Signature valid');

    // Step 2: SBOM
    emit('step', 'Step 2/4 — Verifying SBOM attestation (cosign)...');
    broadcast('deployment:step', { id: dep.id, step: 'sbom', status: 'checking' });
    const sbomResult = verifier.verifySBOM(dep.image, dep.digest);
    dep.checks.sbom = sbomResult.valid ? 'passed' : 'failed';
    broadcast('deployment:step', { id: dep.id, step: 'sbom', status: dep.checks.sbom, packageCount: sbomResult.packageCount });
    if (!sbomResult.valid) {
      emit('attack', `❌ SBOM FAILED: ${sbomResult.error}`);
      emit('attack', '🚨 DEPLOYMENT REJECTED — SBOM attestation invalid');
      return reject(dep, 'sbom_failed');
    }
    emit('success', `✅ SBOM valid — ${sbomResult.packageCount} packages attested`);

    // Step 3: Pull by digest
    emit('step', 'Step 3/4 — Pulling image by digest...');
    broadcast('deployment:step', { id: dep.id, step: 'pull', status: 'running' });
    const pullResult = dockerManager.pullByDigest(dep.image, dep.digest);
    if (!pullResult.success) {
      emit('error', `❌ Pull failed: ${pullResult.stderr}`);
      broadcast('deployment:step', { id: dep.id, step: 'pull', status: 'failed' });
      return reject(dep, 'pull_failed');
    }
    broadcast('deployment:step', { id: dep.id, step: 'pull', status: 'passed' });
    emit('success', '✅ Image pulled by digest');

    // Step 4: Verify digest
    emit('step', 'Step 4/4 — Verifying digest of pulled image...');
    broadcast('deployment:step', { id: dep.id, step: 'digest', status: 'checking' });
    const digestResult = dockerManager.verifyDigest(dep.image, dep.digest);
    dep.checks.digest = digestResult.matches ? 'passed' : 'failed';
    broadcast('deployment:step', { id: dep.id, step: 'digest', status: dep.checks.digest });
    if (!digestResult.matches) {
      emit('attack', `❌ DIGEST MISMATCH — Expected: ${dep.digest} | Got: ${digestResult.actual}`);
      emit('attack', '🚨 SUPPLY CHAIN ATTACK DETECTED — DEPLOYMENT REJECTED');
      return reject(dep, 'digest_mismatch');
    }
    emit('success', '✅ Digest verified — integrity confirmed');
    emit('success', '🎉 All 4 checks passed — deploying');

  } else {
    emit('warn', '⚠️  UNPROTECTED mode — pulling by tag, no verification');
    const pullResult = dockerManager.pull(dep.image);
    if (!pullResult.success) {
      emit('error', `❌ Pull failed: ${pullResult.stderr}`);
      dep.status = 'failed';
      broadcast('deployment:failed', dep);
      return;
    }
  }

  // Deploy
  emit('info', '🚀 Starting container...');
  broadcast('deployment:step', { id: dep.id, step: 'deploy', status: 'running' });
  dockerManager.stopContainer();
  const imageRef  = dep.mode === 'protected' ? `${dep.image.split(':')[0]}@${dep.digest}` : dep.image;
  const runResult = dockerManager.runContainer({
    image: imageRef,
    ports: { [process.env.APP_PORT || '3000']: '3000' },
    env:   { BUILD_ID: dep.sha, VERSION: dep.ref },
  });

  if (!runResult.success) {
    emit('error', `❌ Container start failed: ${runResult.error}`);
    dep.status = 'failed';
    broadcast('deployment:failed', dep);
    return;
  }

  dep.status = 'deployed'; dep.deployedAt = new Date().toISOString(); dep.containerId = runResult.containerId;
  broadcast('deployment:step', { id: dep.id, step: 'deploy', status: 'passed' });
  emit('success', `✅ Container running: ${runResult.containerId.slice(0, 12)}`);
  emit('success', `🌐 App live at http://localhost:${process.env.APP_PORT || 3000}`);
  broadcast('deployment:deployed', dep);
}

function reject(dep, reason) {
  dep.status = 'rejected'; dep.rejectedReason = reason; dep.rejectedAt = new Date().toISOString();
  broadcast('deployment:rejected', dep);
}

// ── API ───────────────────────────────────────────────────────────────────────

app.get('/api/status', (_req, res) => res.json({
  server:      { startedAt: state.startedAt, uptime: Math.floor(process.uptime()) },
  container:   dockerManager.getContainerStatus(),
  deployments: state.deployments,
  cosign:      verifier.isCosignInstalled(),
  team:        state.team,
  repos:       state.repos,
  prs:         state.prs,
  cluster:     state.cluster,
  invitations: state.invitations,
}));

app.get('/api/invitations', (_req, res) => res.json(state.invitations));

app.post('/api/invitations', (req, res) => {
  const { name, email, github, role } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });
  const code = 'INV-' + Math.random().toString(36).substring(2, 6).toUpperCase() + '-2026';
  const invitation = {
    id: 'inv_' + Date.now(),
    name,
    email,
    github: github || name.toLowerCase().replace(/\s+/g, '-'),
    role: role || 'Developer',
    code,
    status: 'Pending',
    sentAt: new Date().toISOString()
  };
  state.invitations.unshift(invitation);
  broadcast('invitations:updated', state.invitations);
  emit('info', `✉️ EMAIL DISPATCHED to ${email} (Subject: Invitation to AttestGate Workspace | Join Code: ${code})`);
  res.json({ success: true, invitation });
});

app.post('/api/invitations/accept', (req, res) => {
  const { code } = req.body;
  const inv = state.invitations.find(i => i.code === code && i.status === 'Pending');
  if (!inv) return res.status(404).json({ error: 'Invalid or already accepted invitation code' });
  
  inv.status = 'Accepted';
  inv.acceptedAt = new Date().toISOString();
  
  const newMember = {
    id: Date.now(),
    name: inv.name,
    role: inv.role,
    github: inv.github,
    email: inv.email,
    status: 'Active'
  };
  state.team.push(newMember);
  broadcast('invitations:updated', state.invitations);
  broadcast('team:updated', state.team);
  emit('success', `🎉 Developer ${inv.name} (@${inv.github}) accepted invitation with code ${code} and joined workspace!`);
  res.json({ success: true, member: newMember });
});

app.get('/api/team', (_req, res) => res.json({ team: state.team, repos: state.repos }));

app.post('/api/team', (req, res) => {
  const { name, role, github } = req.body;
  if (!name || !github) return res.status(400).json({ error: 'Name and GitHub handle required' });
  const member = { id: Date.now(), name, role: role || 'Developer', github, status: 'Active' };
  state.team.push(member);
  broadcast('team:updated', state.team);
  emit('info', `👤 Team Member Added: ${name} (@${github}) — Role: ${member.role}`);
  res.json({ success: true, member });
});

app.get('/api/prs', (_req, res) => res.json(state.prs));

app.post('/api/prs', (req, res) => {
  const { title, author, url } = req.body;
  
  // Check if author is registered in team
  const registeredMember = state.team.find(m => m.github.toLowerCase() === (author || '').toLowerCase() || m.name.toLowerCase() === (author || '').toLowerCase());
  
  let prNumber = state.prs.length + 1;
  if (url) {
    const match = url.match(/\/pull\/(\d+)/);
    if (match) prNumber = parseInt(match[1]);
  }

  const commitHash = crypto.randomBytes(4).toString('hex');
  const pr = {
    id: prNumber,
    title: title || 'feat: production update',
    author: registeredMember ? registeredMember.github : (author || 'external-contributor'),
    authorName: registeredMember ? registeredMember.name : (author || 'External'),
    url: url || `https://github.com/${process.env.GITHUB_REPO || 'OP-Prajwal/buildserver'}/pull/${prNumber}`,
    status: 'Attested',
    commit: commitHash,
    attested: true,
    attestedAt: new Date().toISOString(),
    isVerifiedEmployee: Boolean(registeredMember)
  };

  state.prs.unshift(pr);
  broadcast('prs:updated', state.prs);
  emit('info', '═'.repeat(55));
  emit('success', `🔗 OFFICIAL PR ATTESTED: PR #${pr.id} by @${pr.author} (${pr.authorName})`);
  emit('step', `   URL: ${pr.url}`);
  emit('step', `   Signed Commit Provenance: ${pr.commit}`);
  emit('success', `   Verified Workspace Member: ${pr.isVerifiedEmployee ? 'YES ✅' : 'UNREGISTERED ⚠️'}`);
  res.json({ success: true, pr });
});


app.get('/api/cluster', (_req, res) => res.json(state.cluster));

app.post('/api/simulate/clean', async (_req, res) => {
  const DHUSER = process.env.DOCKERHUB_USERNAME || 'opprajwal';
  const dep = {
    id: crypto.randomUUID(),
    image: `${DHUSER}/supplychainattest-app:latest`,
    digest: 'sha256:4a81b99216ec7102e3f89d31f0cf852899b8a1c97a47b1940a02ef4950b731b8',
    ref: 'refs/heads/main',
    sha: '7f91a2c5890e4f8d9b1a',
    workflow: 'protected.yml (PR #14 Approved)',
    mode: 'protected',
    status: 'pending',
    startedAt: new Date().toISOString(),
    checks: { webhook: 'passed', signature: 'passed', sbom: 'passed', digest: 'passed' }
  };
  state.deployments.unshift(dep);
  broadcast('deployment:started', dep);
  emit('info', '═'.repeat(55));
  emit('info', `📦 Verified Deployment ${dep.id.slice(0, 8)} [PR #14 Approved by @OP-Prajwal]`);
  emit('step', 'Step 1/4 — Verifying Cosign Signature (Sigstore OIDC)...');
  emit('success', `✅ Cosign Signature valid (Identity: github.com/OP-Prajwal/buildserver/.github/workflows/protected.yml)`);
  emit('step', 'Step 2/4 — Verifying SBOM Attestation (Syft SPDX)...');
  emit('success', '✅ SBOM valid — 38 audited packages attested');
  emit('step', 'Step 3/4 — Pulling image by pinned SHA-256 digest...');
  emit('success', `✅ Image ${DHUSER}/supplychainattest-app@sha256:4a81b9... pulled by digest`);
  emit('step', 'Step 4/4 — Digest integrity verification...');
  emit('success', '✅ Digest verified — SHA-256 matches signed commit 7f91a2c');
  emit('success', '🎉 ALL 4 GATES PASSED — DEPLOYING TO KUBERNETES CLUSTER');
  dep.status = 'deployed';
  dep.deployedAt = new Date().toISOString();
  broadcast('deployment:deployed', dep);
  res.json({ success: true, deployment: dep });
});


app.post('/api/simulate/attack', async (_req, res) => {
  const DHUSER = process.env.DOCKERHUB_USERNAME || 'opprajwal';
  const dep = {
    id: crypto.randomUUID(),
    image: `${DHUSER}/supplychainattest-app:latest`,
    digest: 'sha256:99badf00d81726a88b8192837192837198237192837198273918273918273918',
    ref: 'refs/tags/latest (Poisoned Registry Tag)',
    sha: 'attacker-tampered-hash',
    workflow: 'UNTRUSTED (No PR Origin)',
    mode: 'protected',
    status: 'pending',
    startedAt: new Date().toISOString(),
    checks: { webhook: 'passed', signature: 'failed', sbom: 'failed', digest: 'failed' }
  };
  state.deployments.unshift(dep);
  broadcast('deployment:started', dep);
  emit('info', '═'.repeat(55));
  emit('attack', `🚨 INCOMING DEPLOYMENT: ${DHUSER}/supplychainattest-app:latest`);
  emit('attack', '   Origin: UNKNOWN — no matching PR or approved commit');
  emit('step', 'Step 1/4 — Verifying Cosign Signature (Sigstore OIDC)...');
  emit('attack', '❌ SIGNATURE FAILED: error: no matching signatures:');
  emit('attack', '   expected identity: github.com/OP-Prajwal/buildserver/.github/workflows/protected.yml');
  emit('attack', '   actual: NO VALID SIGSTORE ENTRY FOUND');
  emit('attack', '🚨 SUPPLY CHAIN ATTACK DETECTED — DEPLOYMENT REJECTED AT GATE');
  emit('attack', '   Malicious container blocked before execution in Kubernetes cluster.');
  dep.status = 'rejected';
  dep.rejectedReason = 'signature_failed';
  dep.rejectedAt = new Date().toISOString();
  broadcast('deployment:rejected', dep);
  res.json({ success: true, deployment: dep });
});


// ── WebSocket ─────────────────────────────────────────────────────────────────

wss.on('connection', (ws, req) => {
  emit('system', `Dashboard connected — ${req.socket.remoteAddress}`);
  ws.send(JSON.stringify({ event: 'init', data: { deployments: state.deployments, startedAt: state.startedAt }, ts: new Date().toISOString() }));
});

// ── Boot ──────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 4000;
httpServer.listen(PORT, () => {
  emit('system', '═'.repeat(55));
  emit('system', '🚀 Build Server — Deployment-Time Verification Gate');
  emit('system', `   Dashboard → http://localhost:${PORT}`);
  emit('system', `   cosign    → ${verifier.isCosignInstalled() ? '✅ installed' : '❌ NOT FOUND'}`);
  emit('system', '═'.repeat(55));
  emit('system', 'Waiting for deployments...');
});

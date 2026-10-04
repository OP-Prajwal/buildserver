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

const app        = express();
const httpServer = http.createServer(app);
const wss        = new WebSocket.Server({ server: httpServer });

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'dashboard')));

const state = { startedAt: new Date().toISOString(), deployments: [] };

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
}));

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

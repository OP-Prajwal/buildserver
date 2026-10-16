'use strict';

const fs = require('fs');
const https = require('https');
const verifier = require('../build-server/verifier');

const PORT = Number(process.env.PORT || 8443);
const CERT_FILE = process.env.TLS_CERT_FILE || '/tls/tls.crt';
const KEY_FILE = process.env.TLS_KEY_FILE || '/tls/tls.key';
const REQUIRE_SBOM = process.env.REQUIRE_SBOM !== 'false';
const COSIGN_TIMEOUT_MS = Number(process.env.COSIGN_TIMEOUT_MS || 7000);
const CONTROL_PLANE_URL = (process.env.CONTROL_PLANE_URL || '').replace(/\/$/, '');
const CLUSTER_TOKEN = process.env.CLUSTER_TOKEN || '';
const ALLOWED_IMAGE_PREFIXES = (process.env.ALLOWED_IMAGE_PREFIXES || '')
  .split(',').map(prefix => prefix.trim().replace(/\/$/, '')).filter(Boolean);
const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/i;

function imageReferences(review) {
  const object = review?.request?.object;
  if (!object) throw new Error('Admission request has no object');

  let podSpec;
  switch (object.kind) {
    case 'Pod': podSpec = object.spec; break;
    case 'Deployment': case 'StatefulSet': case 'DaemonSet':
    case 'ReplicaSet': case 'ReplicationController': case 'Job':
      podSpec = object.spec?.template?.spec; break;
    case 'CronJob':
      podSpec = object.spec?.jobTemplate?.spec?.template?.spec; break;
    default: throw new Error(`Unsupported workload kind: ${object.kind || 'unknown'}`);
  }

  if (!podSpec) throw new Error(`Missing pod template for ${object.kind}`);
  const containers = [
    ...(podSpec.initContainers || []),
    ...(podSpec.containers || []),
    ...(podSpec.ephemeralContainers || []),
  ];
  if (!containers.length) throw new Error('Workload has no container images');
  return containers.map(container => container.image);
}

async function verifyImage(reference, context = {}) {
  if (CONTROL_PLANE_URL) {
    try {
      const response = await fetch(`${CONTROL_PLANE_URL}/v1/admission/verify`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${CLUSTER_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ image: reference, namespace: context.namespace, workload: context.workload }),
        signal: AbortSignal.timeout(10_000),
      });
      const verdict = await response.json();
      if (!response.ok || typeof verdict.allowed !== 'boolean') {
        return { valid: false, reason: `Control plane verification failed: ${verdict.error || response.statusText}` };
      }
      return verdict.allowed ? { valid: true } : { valid: false, reason: verdict.reason || 'Control plane denied image' };
    } catch (error) {
      return { valid: false, reason: `Control plane unavailable: ${error.message}` };
    }
  }
  if (typeof reference !== 'string' || !reference.includes('@')) {
    return { valid: false, reason: `Image must be pinned by digest: ${reference || '(empty)'}` };
  }
  const at = reference.lastIndexOf('@');
  const image = reference.slice(0, at);
  const digest = reference.slice(at + 1);
  if (!image || !SHA256_DIGEST.test(digest)) {
    return { valid: false, reason: `Invalid SHA-256 image reference: ${reference}` };
  }
  if (!ALLOWED_IMAGE_PREFIXES.some(prefix => image === prefix || image.startsWith(`${prefix}/`))) {
    return { valid: false, reason: `Image is outside configured ALLOWED_IMAGE_PREFIXES: ${image}` };
  }

  const signature = await verifier.verifySignatureAsync(image, digest, COSIGN_TIMEOUT_MS);
  if (!signature.valid) return { valid: false, reason: `Cosign signature verification failed for ${reference}: ${signature.error}` };
  if (REQUIRE_SBOM) {
    const sbom = await verifier.verifySBOMAsync(image, digest, COSIGN_TIMEOUT_MS);
    if (!sbom.valid) return { valid: false, reason: `SBOM attestation verification failed for ${reference}: ${sbom.error}` };
  }
  return { valid: true };
}

async function verifyImages(references, concurrency = 4, context = {}) {
  const results = new Array(references.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, references.length) }, async () => {
    while (next < references.length) {
      const index = next++;
      results[index] = await verifyImage(references[index], context);
    }
  });
  await Promise.all(workers);
  return results;
}

function admissionResponse(review, allowed, message) {
  return {
    apiVersion: 'admission.k8s.io/v1',
    kind: 'AdmissionReview',
    response: {
      uid: review?.request?.uid || '',
      allowed,
      ...(message ? { status: { code: 403, message } } : {}),
    },
  };
}

function handle(req, res) {
  if (req.method === 'GET' && req.url === '/healthz') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    return res.end('ok');
  }
  if (req.method !== 'POST' || req.url !== '/validate') {
    res.writeHead(404).end();
    return;
  }

  let body = '';
  req.on('data', chunk => { body += chunk; if (body.length > 2_000_000) req.destroy(); });
  req.on('end', async () => {
    let review;
    try {
      review = JSON.parse(body);
      if (review.apiVersion !== 'admission.k8s.io/v1' || review.kind !== 'AdmissionReview' || !review.request) {
        throw new Error('Expected admission.k8s.io/v1 AdmissionReview');
      }
      const refs = imageReferences(review);
      const object = review.request.object;
      const namespace = review.request.namespace || object.metadata?.namespace || '';
      const kind = review.request.kind?.kind || object.kind || 'Workload';
      const workload = `${kind}/${object.metadata?.name || 'unnamed'}`;
      const results = await verifyImages(refs, 4, { namespace, workload });
      const failure = results.find(result => !result.valid);
      if (failure) {
        console.warn(`[deny] ${failure.reason}`);
        return send(admissionResponse(review, false, failure.reason));
      }
      return send(admissionResponse(review, true));
    } catch (error) {
      console.error(`[deny] ${error.message}`);
      return send(admissionResponse(review, false, error.message));
    }
  });

  function send(response) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(response));
  }
}

function validateConfiguration() {
  if (!Number.isInteger(COSIGN_TIMEOUT_MS) || COSIGN_TIMEOUT_MS < 100 || COSIGN_TIMEOUT_MS > 10_000) {
    throw new Error('COSIGN_TIMEOUT_MS must be an integer between 100 and 10000');
  }
  if (CONTROL_PLANE_URL) {
    const controlPlane = new URL(CONTROL_PLANE_URL);
    if (controlPlane.protocol !== 'https:' && controlPlane.hostname !== 'localhost') {
      throw new Error('CONTROL_PLANE_URL must use HTTPS outside localhost');
    }
    if (!CLUSTER_TOKEN || CLUSTER_TOKEN.startsWith('REPLACE_')) throw new Error('CLUSTER_TOKEN is required when CONTROL_PLANE_URL is configured');
  } else {
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(process.env.GITHUB_REPO || '')) {
      throw new Error('GITHUB_REPO must be set to a GitHub owner/repository');
    }
    if (!ALLOWED_IMAGE_PREFIXES.length || ALLOWED_IMAGE_PREFIXES.some(prefix => prefix.startsWith('REPLACE_'))) {
      throw new Error('ALLOWED_IMAGE_PREFIXES must contain one or more configured image repositories');
    }
    if (!verifier.isCosignInstalled()) throw new Error('cosign executable is unavailable');
  }
  if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
    throw new Error(`Webhook TLS certificate and key are required at ${CERT_FILE} and ${KEY_FILE}`);
  }
}

function start() {
  validateConfiguration();
  const server = https.createServer({ cert: fs.readFileSync(CERT_FILE), key: fs.readFileSync(KEY_FILE) }, handle);
  server.headersTimeout = 10_000;
  server.requestTimeout = 20_000;
  server.listen(PORT, '0.0.0.0', () => console.log(`AttestGate admission webhook listening on ${PORT}`));
  return server;
}

if (require.main === module) {
  try { start(); }
  catch (error) {
    console.error(`[startup] ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { imageReferences, verifyImage, verifyImages, admissionResponse, validateConfiguration, start };

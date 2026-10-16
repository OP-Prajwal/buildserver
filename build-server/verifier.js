'use strict';

const { spawnSync } = require('child_process');
const { execFile } = require('child_process');
const { promisify } = require('util');
const logger = require('./logger');
const execFileAsync = promisify(execFile);

const COSIGN_BIN = process.platform === 'win32' ? 'cosign-windows-amd64' : 'cosign';
const GITHUB_REPO      = process.env.GITHUB_REPO;
const TRUSTED_BRANCH   = process.env.TRUSTED_BRANCH   || 'main';
const TRUSTED_WORKFLOW = process.env.TRUSTED_WORKFLOW  || 'protected.yml';
const OIDC_ISSUER      = 'https://token.actions.githubusercontent.com';

function trustedWorkflowIdentity(repository = GITHUB_REPO, workflow = TRUSTED_WORKFLOW, branch = TRUSTED_BRANCH) {
  if (!repository) throw new Error('GITHUB_REPO env var is not set');
  return `https://github.com/${repository}/.github/workflows/${workflow}@refs/heads/${branch}`;
}

function isCosignInstalled() {
  const r = spawnSync(COSIGN_BIN, ['version'], { stdio: 'pipe' });
  return r.status === 0;
}

function normalizeTimeout(timeoutMs) {
  const timeout = Number(timeoutMs);
  return Number.isFinite(timeout) && timeout > 0 ? Math.min(timeout, 120_000) : 60_000;
}

function parseJsonDocuments(output) {
  const text = String(output || '').trim();
  if (!text) return [];

  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch { /* Cosign can also emit newline-delimited or pretty-printed JSON records. */ }

  const documents = [];
  let start = -1;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (start < 0) {
      if (character !== '{' && character !== '[') continue;
      start = index;
      depth = 1;
      continue;
    }
    if (inString) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === '{' || character === '[') depth++;
    else if (character === '}' || character === ']') depth--;
    if (depth === 0) {
      try { documents.push(JSON.parse(text.slice(start, index + 1))); } catch { /* Ignore non-JSON log fragments. */ }
      start = -1;
    }
  }
  return documents;
}

async function runCosign(args, timeoutMs) {
  try {
    return await execFileAsync(COSIGN_BIN, args, {
      encoding: 'utf8',
      timeout: normalizeTimeout(timeoutMs),
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (error) {
    error.cosignOutput = error.stderr || error.stdout || '';
    throw error;
  }
}

function verifySignature(image, digest, timeoutMs = 60_000) {
  if (!isCosignInstalled()) return { valid: false, error: 'cosign not installed' };
  const ref      = `${image}@${digest}`;
  const identity = trustedWorkflowIdentity();
  logger.step(`cosign verify --certificate-identity="${identity}" ${ref}`);
  const r = spawnSync(COSIGN_BIN, [
    'verify',
    `--certificate-identity=${identity}`,
    `--certificate-oidc-issuer=${OIDC_ISSUER}`,
    '--output=json', ref,
  ], { encoding: 'utf8', timeout: normalizeTimeout(timeoutMs) });
  if (r.status !== 0) return { valid: false, error: (r.error?.message || r.stderr || r.stdout || '').trim() };
  return { valid: true };
}

function verifySBOM(image, digest, timeoutMs = 60_000) {
  if (!isCosignInstalled()) return { valid: false, error: 'cosign not installed' };
  const ref      = `${image}@${digest}`;
  const identity = trustedWorkflowIdentity();
  logger.step(`cosign verify-attestation --type=spdxjson ${ref}`);
  const r = spawnSync(COSIGN_BIN, [
    'verify-attestation',
    '--type=spdxjson',
    `--certificate-identity=${identity}`,
    `--certificate-oidc-issuer=${OIDC_ISSUER}`,
    ref,
  ], { encoding: 'utf8', timeout: normalizeTimeout(timeoutMs) });
  if (r.status !== 0) return { valid: false, error: (r.error?.message || r.stderr || r.stdout || '').trim() };

  let packageCount = 0;
  try {
    const lines      = r.stdout.trim().split('\n');
    const att        = JSON.parse(lines[0]);
    const payload    = Buffer.from(att.payload, 'base64').toString('utf8');
    const predicate  = JSON.parse(payload);
    const sbom       = predicate.predicate || predicate;
    packageCount     = sbom?.packages?.length ?? 0;
  } catch { /* non-fatal */ }

  return { valid: true, packageCount };
}

async function verifySignatureAsync(image, digest, timeoutMs = 60_000, expectedIdentity) {
  const ref = `${image}@${digest}`;
  let identity;
  try { identity = expectedIdentity || trustedWorkflowIdentity(); }
  catch (error) { return { valid: false, error: error.message }; }
  logger.step(`cosign verify --certificate-identity="${identity}" ${ref}`);
  try {
    await runCosign([
      'verify',
      `--certificate-identity=${identity}`,
      `--certificate-oidc-issuer=${OIDC_ISSUER}`,
      '--output=json', ref,
    ], timeoutMs);
    return { valid: true };
  } catch (error) {
    return { valid: false, error: (error.cosignOutput || error.message || '').trim() };
  }
}

async function verifySBOMAsync(image, digest, timeoutMs = 60_000, expectedIdentity) {
  const ref = `${image}@${digest}`;
  let identity;
  try { identity = expectedIdentity || trustedWorkflowIdentity(); }
  catch (error) { return { valid: false, error: error.message }; }
  logger.step(`cosign verify-attestation --type=spdxjson ${ref}`);
  let stdout;
  try {
    ({ stdout } = await runCosign([
      'verify-attestation',
      '--type=spdxjson',
      `--certificate-identity=${identity}`,
      `--certificate-oidc-issuer=${OIDC_ISSUER}`,
      ref,
    ], timeoutMs));
  } catch (error) {
    return { valid: false, error: (error.cosignOutput || error.message || '').trim() };
  }

  let packageCount = 0;
  try {
    const att = parseJsonDocuments(stdout).find(document => document?.payload);
    if (!att) throw new Error('Cosign returned no attestation payload');
    const predicate = JSON.parse(Buffer.from(att.payload, 'base64').toString('utf8'));
    packageCount = (predicate.predicate || predicate)?.packages?.length ?? 0;
  } catch { /* package count is informational */ }
  return { valid: true, packageCount };
}

async function verifyProvenanceAsync(image, digest, timeoutMs = 60_000, expectedIdentity, expected = {}) {
  const ref = `${image}@${digest}`;
  const observed = [];
  try {
    const { stdout } = await runCosign([
      'verify-attestation', '--type=custom',
      `--certificate-identity=${expectedIdentity || trustedWorkflowIdentity()}`,
      `--certificate-oidc-issuer=${OIDC_ISSUER}`, ref,
    ], timeoutMs);
    for (const envelope of parseJsonDocuments(stdout)) {
      try {
        const statement = JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8'));
        const predicate = statement.predicate || {};
        const subjects = Array.isArray(statement.subject) ? statement.subject : [];
        observed.push({
          statementType: statement._type,
          predicateType: statement.predicateType,
          subjects: subjects.slice(0, 3).map(subject => ({ name: subject.name, sha256: subject.digest?.sha256 })),
          predicate: {
            imageRepository: predicate.imageRepository,
            sourceRepository: predicate.sourceRepository,
            commitSha: predicate.commitSha,
            sourceRef: predicate.sourceRef,
          },
        });
        if (!['https://in-toto.io/Statement/v0.1', 'https://in-toto.io/Statement/v1'].includes(statement._type) ||
            statement.predicateType !== 'https://cosign.sigstore.dev/attestation/v1' ||
            !subjects.some(subject =>
              subject.name === image && subject.digest?.sha256 === digest.slice('sha256:'.length))) continue;
        if (predicate.imageRepository === expected.imageRepository &&
            predicate.sourceRepository === expected.sourceRepository &&
            predicate.commitSha === expected.commitSha && predicate.sourceRef === expected.sourceRef) {
          return { valid: true, provenance: predicate };
        }
      } catch { /* inspect the next verified statement */ }
    }
    return {
      valid: false,
      error: JSON.stringify({
        message: 'No signed provenance statement matches the image digest and configured source',
        expected: {
          imageRepository: expected.imageRepository,
          digest: digest.slice('sha256:'.length),
          sourceRepository: expected.sourceRepository,
          commitSha: expected.commitSha,
          sourceRef: expected.sourceRef,
        },
        observed: observed.slice(0, 3),
      }),
    };
  } catch (error) {
    return { valid: false, error: (error.cosignOutput || error.message || '').trim() };
  }
}

module.exports = {
  verifySignature,
  verifySBOM,
  verifySignatureAsync,
  verifySBOMAsync,
  verifyProvenanceAsync,
  isCosignInstalled,
};

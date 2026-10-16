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
    const att = JSON.parse(stdout.trim().split('\n')[0]);
    const predicate = JSON.parse(Buffer.from(att.payload, 'base64').toString('utf8'));
    packageCount = (predicate.predicate || predicate)?.packages?.length ?? 0;
  } catch { /* package count is informational */ }
  return { valid: true, packageCount };
}

async function verifyProvenanceAsync(image, digest, timeoutMs = 60_000, expectedIdentity, expected = {}) {
  const ref = `${image}@${digest}`;
  try {
    const { stdout } = await runCosign([
      'verify-attestation', '--type=custom',
      `--certificate-identity=${expectedIdentity || trustedWorkflowIdentity()}`,
      `--certificate-oidc-issuer=${OIDC_ISSUER}`, ref,
    ], timeoutMs);
    for (const line of stdout.trim().split(/\r?\n/)) {
      try {
        const envelope = JSON.parse(line);
        const statement = JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8'));
        const predicate = statement.predicate || {};
        if (!['https://in-toto.io/Statement/v0.1', 'https://in-toto.io/Statement/v1'].includes(statement._type) ||
            statement.predicateType !== 'https://cosign.sigstore.dev/attestation/v1' ||
            !Array.isArray(statement.subject) || !statement.subject.some(subject =>
              subject.name === image && subject.digest?.sha256 === digest.slice('sha256:'.length))) continue;
        if (predicate.imageRepository === expected.imageRepository &&
            predicate.sourceRepository === expected.sourceRepository &&
            predicate.commitSha === expected.commitSha && predicate.sourceRef === expected.sourceRef) {
          return { valid: true, provenance: predicate };
        }
      } catch { /* inspect the next verified statement */ }
    }
    return { valid: false, error: 'No signed provenance statement matches the image digest and configured source' };
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

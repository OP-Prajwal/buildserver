'use strict';

const { spawnSync } = require('child_process');
const logger = require('./logger');

const COSIGN_BIN = process.platform === 'win32' ? 'cosign-windows-amd64' : 'cosign';
const GITHUB_REPO      = process.env.GITHUB_REPO;
const TRUSTED_BRANCH   = process.env.TRUSTED_BRANCH   || 'main';
const TRUSTED_WORKFLOW = process.env.TRUSTED_WORKFLOW  || 'protected.yml';
const OIDC_ISSUER      = 'https://token.actions.githubusercontent.com';

function trustedWorkflowIdentity() {
  if (!GITHUB_REPO) throw new Error('GITHUB_REPO env var is not set');
  return `https://github.com/${GITHUB_REPO}/.github/workflows/${TRUSTED_WORKFLOW}@refs/heads/${TRUSTED_BRANCH}`;
}

function isCosignInstalled() {
  const r = spawnSync(COSIGN_BIN, ['version'], { stdio: 'pipe' });
  return r.status === 0;
}

function verifySignature(image, digest) {
  if (!isCosignInstalled()) return { valid: false, error: 'cosign not installed' };
  const ref      = `${image}@${digest}`;
  const identity = trustedWorkflowIdentity();
  logger.step(`cosign verify --certificate-identity="${identity}" ${ref}`);
  const r = spawnSync(COSIGN_BIN, [
    'verify',
    `--certificate-identity=${identity}`,
    `--certificate-oidc-issuer=${OIDC_ISSUER}`,
    '--output=json', ref,
  ], { encoding: 'utf8', timeout: 60_000 });
  if (r.status !== 0) return { valid: false, error: (r.stderr || r.stdout || '').trim() };
  return { valid: true };
}

function verifySBOM(image, digest) {
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
  ], { encoding: 'utf8', timeout: 60_000 });
  if (r.status !== 0) return { valid: false, error: (r.stderr || r.stdout || '').trim() };

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

module.exports = { verifySignature, verifySBOM, isCosignInstalled };

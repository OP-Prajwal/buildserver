'use strict';

const { spawnSync } = require('child_process');
const logger = require('./logger');

const APP_CONTAINER_NAME = process.env.APP_CONTAINER_NAME || 'supplychainattest-app';
const APP_PORT           = process.env.APP_PORT           || '3000';

function run(args) {
  logger.step(`docker ${args.join(' ')}`);
  const r = spawnSync('docker', args, { encoding: 'utf8', timeout: 120_000 });
  return { success: r.status === 0, stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim() };
}

function pull(image) {
  logger.info(`Pulling ${image} by tag (unprotected)`);
  return run(['pull', image]);
}

function pullByDigest(image, digest) {
  const ref = `${image.split(':')[0]}@${digest}`;
  logger.info(`Pulling ${ref} by digest (tamper-proof)`);
  return run(['pull', ref]);
}

function verifyDigest(image, digest) {
  const ref = `${image.split(':')[0]}@${digest}`;
  const r   = run(['inspect', '--format', '{{json .RepoDigests}}', ref]);
  if (!r.success) return { matches: false, error: r.stderr, actual: null };
  let repoDigests = [];
  try { repoDigests = JSON.parse(r.stdout); } catch { return { matches: false, error: 'parse error', actual: r.stdout }; }
  const actual  = repoDigests.map(d => d.split('@')[1]).find(d => d?.startsWith('sha256:'));
  return { matches: actual === digest, actual: actual ?? 'unknown', expected: digest };
}

function stopContainer(name = APP_CONTAINER_NAME) {
  const exists = run(['inspect', '--format', '{{.State.Status}}', name]);
  if (!exists.success) return { success: true, skipped: true };
  run(['stop', name]);
  run(['rm', '-f', name]);
  return { success: true };
}

function runContainer({ image, name = APP_CONTAINER_NAME, ports = {}, env = {} }) {
  const args = ['run', '-d', '--name', name, '--restart', 'unless-stopped'];
  for (const [h, c] of Object.entries(ports)) args.push('-p', `${h}:${c}`);
  for (const [k, v] of Object.entries(env))   args.push('-e', `${k}=${v}`);
  args.push(image);
  const r = run(args);
  return r.success ? { success: true, containerId: r.stdout } : { success: false, error: r.stderr };
}

function getContainerStatus(name = APP_CONTAINER_NAME) {
  const r = run(['inspect', '--format', '{{json .State}}', name]);
  if (!r.success) return null;
  try { return JSON.parse(r.stdout); } catch { return null; }
}

module.exports = { pull, pullByDigest, verifyDigest, stopContainer, runContainer, getContainerStatus };

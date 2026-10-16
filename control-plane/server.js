'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const { Pool } = require('pg');
const verifierPath = fs.existsSync(path.resolve(__dirname, '../build-server/verifier.js'))
  ? '../build-server/verifier'
  : './build-server/verifier';
const verifier = require(verifierPath);

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.DB_POOL_SIZE || 10),
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30_000,
});
pool.on('error', error => console.error('[database] idle connection error', error.message));

const PORT = Number(process.env.PORT || 4100);
const APP_BASE_URL = (process.env.APP_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
const SESSION_TTL_DAYS = 14;
const TOKEN_BYTES = 32;
const COSIGN_TIMEOUT_MS = Number(process.env.COSIGN_TIMEOUT_MS || 15_000);
const TOKEN_COOKIE = 'attestgate_session';
const CSRF_COOKIE = 'attestgate_csrf';
const OAUTH_COOKIE = 'attestgate_oauth_state';
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

app.disable('x-powered-by');
app.use(express.json({ limit: '128kb' }));
app.use((_req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
  if (COOKIE_SECURE) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', etag: true }));

function randomToken(bytes = TOKEN_BYTES) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left || ''));
  const b = Buffer.from(String(right || ''));
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}

function cookieValue(req, name) {
  const header = req.headers.cookie || '';
  for (const item of header.split(';')) {
    const at = item.indexOf('=');
    if (at < 0 || item.slice(0, at).trim() !== name) continue;
    try { return decodeURIComponent(item.slice(at + 1).trim()); } catch { return ''; }
  }
  return '';
}

function setCookie(res, name, value, { httpOnly = true, maxAge = 0, sameSite = 'Lax' } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', `SameSite=${sameSite}`];
  if (httpOnly) parts.push('HttpOnly');
  if (COOKIE_SECURE) parts.push('Secure');
  if (maxAge) parts.push(`Max-Age=${maxAge}`);
  res.append('Set-Cookie', parts.join('; '));
}

function clearCookie(res, name, options = {}) {
  const parts = [`${name}=`, 'Path=/', 'Max-Age=0', `SameSite=${options.sameSite || 'Lax'}`];
  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (COOKIE_SECURE) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function sendError(res, status, message) {
  return res.status(status).json({ error: message });
}

function validateProjectId(id) {
  return UUID.test(id || '');
}

function slugify(value) {
  return String(value || '').normalize('NFKD').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 63);
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeBranch(value) {
  const branch = String(value || '').trim();
  if (!/^[A-Za-z0-9_./-]{1,120}$/.test(branch) || branch.includes('..') || branch.startsWith('/') || branch.endsWith('/')) return null;
  return branch;
}

function normalizeWorkflow(value) {
  const workflow = String(value || '').trim().replace(/^\.github\/workflows\//, '');
  if (!/^[A-Za-z0-9_.\/-]{1,180}\.ya?ml$/.test(workflow) || workflow.split('/').includes('..')) return null;
  return workflow;
}

function identityFor(integration) {
  return `https://github.com/${integration.repository}/.github/workflows/${integration.workflow_file}@refs/heads/${integration.branch}`;
}

function parseImageReference(reference) {
  if (typeof reference !== 'string') return null;
  const at = reference.lastIndexOf('@');
  if (at < 1) return null;
  let repository = reference.slice(0, at);
  const digest = reference.slice(at + 1);
  if (!SHA256.test(digest) || repository.length > 255 || /\s/.test(repository) || repository.includes('@')) return null;
  const lastSlash = repository.lastIndexOf('/');
  const lastColon = repository.lastIndexOf(':');
  if (lastColon > lastSlash) repository = repository.slice(0, lastColon);
  return { repository, digest };
}

function requireUser(req, res, next) {
  const raw = cookieValue(req, TOKEN_COOKIE);
  if (!raw) return sendError(res, 401, 'Sign in with GitHub to continue');
  pool.query(
    `SELECT s.csrf_hash, u.id, u.github_login, u.display_name, u.email
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > now()`, [hash(raw)]
  ).then(result => {
    if (!result.rowCount) return sendError(res, 401, 'Session expired; sign in again');
    req.user = result.rows[0];
    req.csrfHash = result.rows[0].csrf_hash;
    next();
  }).catch(next);
}

function requireCsrf(req, res, next) {
  const origin = req.get('origin');
  if (origin && origin !== APP_BASE_URL) return sendError(res, 403, 'Origin is not allowed');
  const csrf = cookieValue(req, CSRF_COOKIE);
  const header = req.get('x-csrf-token');
  if (!csrf || !safeEqual(csrf, header) || !safeEqual(hash(csrf), req.csrfHash)) {
    return sendError(res, 403, 'CSRF token is invalid');
  }
  next();
}

function userMutation(handler) {
  return [requireUser, requireCsrf, asyncRoute(handler)];
}

async function projectRole(projectId, userId) {
  if (!validateProjectId(projectId)) return null;
  const result = await pool.query(
    'SELECT role FROM project_members WHERE project_id = $1 AND user_id = $2', [projectId, userId]
  );
  return result.rows[0]?.role || null;
}

function hasRole(role, allowed) {
  return allowed.includes(role);
}

function requireBearer(req, res, next) {
  const [scheme, token] = String(req.get('authorization') || '').split(' ');
  if (scheme !== 'Bearer' || !token || token.length > 512) return sendError(res, 401, 'Bearer token required');
  req.bearerHash = hash(token);
  next();
}

async function migrate() {
  await pool.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
}

app.get('/healthz', asyncRoute(async (_req, res) => {
  await pool.query('SELECT 1');
  res.json({ status: 'ok' });
}));

app.get('/auth/github', (_req, res) => {
  const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
  if (!clientId) return sendError(res, 503, 'GitHub OAuth is not configured');
  const state = randomToken(24);
  setCookie(res, OAUTH_COOKIE, state, { sameSite: 'Lax', maxAge: 600 });
  const callback = `${APP_BASE_URL}/auth/github/callback`;
  const query = new URLSearchParams({ client_id: clientId, redirect_uri: callback, scope: 'read:user user:email', state });
  res.redirect(`https://github.com/login/oauth/authorize?${query}`);
});

app.get('/auth/github/callback', asyncRoute(async (req, res) => {
  const stateCookie = cookieValue(req, OAUTH_COOKIE);
  clearCookie(res, OAUTH_COOKIE);
  if (!safeEqual(stateCookie, req.query.state)) return sendError(res, 400, 'GitHub authorization state did not match');
  if (!req.query.code || !process.env.GITHUB_OAUTH_CLIENT_SECRET) return sendError(res, 400, 'GitHub authorization failed');

  const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.GITHUB_OAUTH_CLIENT_ID,
      client_secret: process.env.GITHUB_OAUTH_CLIENT_SECRET,
      code: req.query.code,
      redirect_uri: `${APP_BASE_URL}/auth/github/callback`,
    }),
    signal: AbortSignal.timeout(10_000),
  });
  const tokenData = await tokenResponse.json();
  if (!tokenResponse.ok || tokenData.error || !tokenData.access_token) return sendError(res, 401, 'GitHub sign-in failed');

  const githubHeaders = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${tokenData.access_token}`,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'AttestGate-Control-Plane',
  };
  const [profileResponse, emailsResponse] = await Promise.all([
    fetch('https://api.github.com/user', { headers: githubHeaders, signal: AbortSignal.timeout(10_000) }),
    fetch('https://api.github.com/user/emails', { headers: githubHeaders, signal: AbortSignal.timeout(10_000) }),
  ]);
  if (!profileResponse.ok || !emailsResponse.ok) return sendError(res, 502, 'Could not read the GitHub account');
  const [profile, emails] = await Promise.all([profileResponse.json(), emailsResponse.json()]);
  const primaryEmail = emails.find(item => item.primary && item.verified)?.email;
  if (!primaryEmail) return sendError(res, 403, 'Your GitHub account needs a verified primary email address');

  const userResult = await pool.query(
    `INSERT INTO users (id, github_id, github_login, display_name, email)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (github_id) DO UPDATE SET github_login = EXCLUDED.github_login,
       display_name = EXCLUDED.display_name, email = EXCLUDED.email, updated_at = now()
     RETURNING id`,
    [crypto.randomUUID(), String(profile.id), profile.login, profile.name || profile.login, normalizeEmail(primaryEmail)]
  );

  const sessionToken = randomToken();
  const csrfToken = randomToken(24);
  await pool.query(
    'INSERT INTO sessions (token_hash, user_id, csrf_hash, expires_at) VALUES ($1, $2, $3, now() + $4::interval)',
    [hash(sessionToken), userResult.rows[0].id, hash(csrfToken), `${SESSION_TTL_DAYS} days`]
  );
  setCookie(res, TOKEN_COOKIE, sessionToken, { httpOnly: true, maxAge: SESSION_TTL_DAYS * 86400 });
  setCookie(res, CSRF_COOKIE, csrfToken, { httpOnly: false, sameSite: 'Strict', maxAge: SESSION_TTL_DAYS * 86400 });
  res.redirect('/');
}));

app.get('/api/me', requireUser, (req, res) => {
  res.json({
    user: { id: req.user.id, githubLogin: req.user.github_login, displayName: req.user.display_name, email: req.user.email },
    csrfToken: cookieValue(req, CSRF_COOKIE),
  });
});

app.post('/auth/logout', ...userMutation(async (req, res) => {
  await pool.query('DELETE FROM sessions WHERE token_hash = $1', [hash(cookieValue(req, TOKEN_COOKIE))]);
  clearCookie(res, TOKEN_COOKIE);
  clearCookie(res, CSRF_COOKIE, { httpOnly: false, sameSite: 'Strict' });
  res.json({ ok: true });
}));

app.get('/api/projects', requireUser, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT p.id, p.name, p.slug, p.created_at, m.role,
       (SELECT count(*)::int FROM clusters c WHERE c.project_id = p.id AND c.status = 'active') AS cluster_count,
       (SELECT count(*)::int FROM artifacts a WHERE a.project_id = p.id) AS artifact_count
     FROM projects p JOIN project_members m ON m.project_id = p.id
     WHERE m.user_id = $1 ORDER BY p.created_at DESC`, [req.user.id]
  );
  res.json({ projects: result.rows });
}));

app.post('/api/projects', ...userMutation(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const slug = slugify(req.body.slug || name);
  if (name.length < 2 || name.length > 100 || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(slug)) {
    return sendError(res, 400, 'Provide a project name and a valid 2â€“63 character project slug');
  }
  const client = await pool.connect();
  const projectId = crypto.randomUUID();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO projects (id, name, slug, created_by) VALUES ($1, $2, $3, $4)', [projectId, name, slug, req.user.id]);
    await client.query('INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, $3)', [projectId, req.user.id, 'owner']);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.code === '23505') return sendError(res, 409, 'That project slug is already in use');
    throw error;
  } finally { client.release(); }
  res.status(201).json({ project: { id: projectId, name, slug, role: 'owner' } });
}));

app.get('/api/projects/:projectId', requireUser, asyncRoute(async (req, res) => {
  const role = await projectRole(req.params.projectId, req.user.id);
  if (!role) return sendError(res, 404, 'Project not found');
  const result = await pool.query(
    `SELECT p.id, p.name, p.slug, p.created_at,
       (SELECT count(*)::int FROM project_members m WHERE m.project_id = p.id) AS member_count,
       (SELECT count(*)::int FROM ci_integrations i WHERE i.project_id = p.id AND i.enabled) AS integration_count,
       (SELECT count(*)::int FROM clusters c WHERE c.project_id = p.id AND c.status = 'active') AS cluster_count,
       (SELECT count(*)::int FROM artifacts a WHERE a.project_id = p.id) AS artifact_count
       FROM projects p WHERE p.id = $1`, [req.params.projectId]
  );
  res.json({ project: { ...result.rows[0], role } });
}));

app.get('/api/projects/:projectId/members', requireUser, asyncRoute(async (req, res) => {
  if (!await projectRole(req.params.projectId, req.user.id)) return sendError(res, 404, 'Project not found');
  const result = await pool.query(
    `SELECT u.id, u.github_login, u.display_name, u.email, m.role, m.joined_at
       FROM project_members m JOIN users u ON u.id = m.user_id
      WHERE m.project_id = $1 ORDER BY m.joined_at`, [req.params.projectId]
  );
  res.json({ members: result.rows });
}));

app.patch('/api/projects/:projectId/members/:memberId', ...userMutation(async (req, res) => {
  const actorRole = await projectRole(req.params.projectId, req.user.id);
  if (!hasRole(actorRole, ['owner', 'admin'])) return sendError(res, actorRole ? 403 : 404, 'Project administrator access required');
  if (!['admin', 'engineer', 'viewer'].includes(req.body.role)) return sendError(res, 400, 'Role must be admin, engineer, or viewer');
  const targetRole = await projectRole(req.params.projectId, req.params.memberId);
  if (!targetRole || targetRole === 'owner') return sendError(res, 404, 'Member not found or cannot be changed');
  if (actorRole !== 'owner' && (targetRole === 'admin' || req.body.role === 'admin')) {
    return sendError(res, 403, 'Only the project owner can change administrator roles');
  }
  await pool.query('UPDATE project_members SET role = $1 WHERE project_id = $2 AND user_id = $3', [req.body.role, req.params.projectId, req.params.memberId]);
  res.json({ updated: true, role: req.body.role });
}));

app.delete('/api/projects/:projectId/members/:memberId', ...userMutation(async (req, res) => {
  const actorRole = await projectRole(req.params.projectId, req.user.id);
  if (!hasRole(actorRole, ['owner', 'admin'])) return sendError(res, actorRole ? 403 : 404, 'Project administrator access required');
  const targetRole = await projectRole(req.params.projectId, req.params.memberId);
  if (!targetRole || targetRole === 'owner') return sendError(res, 404, 'Member not found or cannot be removed');
  if (actorRole !== 'owner' && targetRole === 'admin') return sendError(res, 403, 'Only the project owner can remove an administrator');
  await pool.query('DELETE FROM project_members WHERE project_id = $1 AND user_id = $2', [req.params.projectId, req.params.memberId]);
  res.json({ removed: true });
}));

app.get('/api/projects/:projectId/invitations', requireUser, asyncRoute(async (req, res) => {
  const role = await projectRole(req.params.projectId, req.user.id);
  if (!hasRole(role, ['owner', 'admin'])) return sendError(res, role ? 403 : 404, 'Project administrator access required');
  const result = await pool.query(
    `SELECT id, email, role, expires_at, accepted_at, revoked_at, created_at
       FROM invitations WHERE project_id = $1 ORDER BY created_at DESC`, [req.params.projectId]
  );
  res.json({ invitations: result.rows });
}));

app.post('/api/projects/:projectId/invitations', ...userMutation(async (req, res) => {
  const role = await projectRole(req.params.projectId, req.user.id);
  if (!hasRole(role, ['owner', 'admin'])) return sendError(res, role ? 403 : 404, 'Project administrator access required');
  const email = normalizeEmail(req.body.email);
  const inviteRole = req.body.role || 'engineer';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return sendError(res, 400, 'A valid email address is required');
  if (!['admin', 'engineer', 'viewer'].includes(inviteRole)) return sendError(res, 400, 'Invalid project role');
  const token = randomToken(32);
  const invitationId = crypto.randomUUID();
  const result = await pool.query(
    `INSERT INTO invitations (id, project_id, email, role, token_hash, invited_by, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, now() + interval '7 days')
     RETURNING id, email, role, expires_at, created_at`,
    [invitationId, req.params.projectId, email, inviteRole, hash(token), req.user.id]
  );
  const inviteUrl = `${APP_BASE_URL}/#invite=${token}`;
  res.status(201).json({ invitation: result.rows[0], inviteUrl, delivery: 'copy_link' });
}));

app.delete('/api/projects/:projectId/invitations/:invitationId', ...userMutation(async (req, res) => {
  const role = await projectRole(req.params.projectId, req.user.id);
  if (!hasRole(role, ['owner', 'admin'])) return sendError(res, role ? 403 : 404, 'Project administrator access required');
  const result = await pool.query(
    `UPDATE invitations SET revoked_at = now()
      WHERE id = $1 AND project_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL
      RETURNING id`, [req.params.invitationId, req.params.projectId]
  );
  if (!result.rowCount) return sendError(res, 404, 'Pending invitation not found');
  res.json({ revoked: true });
}));

app.post('/api/invitations/accept', ...userMutation(async (req, res) => {
  const token = String(req.body.token || '');
  if (token.length < 32 || token.length > 128) return sendError(res, 400, 'Invalid invitation');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const inviteResult = await client.query(
      `SELECT * FROM invitations WHERE token_hash = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now() FOR UPDATE`, [hash(token)]
    );
    const invitation = inviteResult.rows[0];
    if (!invitation || normalizeEmail(invitation.email) !== normalizeEmail(req.user.email)) {
      await client.query('ROLLBACK');
      return sendError(res, 404, 'Invitation is invalid, expired, or belongs to another email address');
    }
    await client.query(
      `INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, $3)
       ON CONFLICT (project_id, user_id) DO NOTHING`,
      [invitation.project_id, req.user.id, invitation.role]
    );
    await client.query('UPDATE invitations SET accepted_by = $1, accepted_at = now() WHERE id = $2', [req.user.id, invitation.id]);
    await client.query('COMMIT');
    const membership = await client.query('SELECT role FROM project_members WHERE project_id = $1 AND user_id = $2', [invitation.project_id, req.user.id]);
    res.json({ joined: true, projectId: invitation.project_id, role: membership.rows[0].role });
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
}));

app.post('/api/projects/:projectId/integrations', ...userMutation(async (req, res) => {
  const role = await projectRole(req.params.projectId, req.user.id);
  if (!hasRole(role, ['owner', 'admin'])) return sendError(res, role ? 403 : 404, 'Project administrator access required');
  const name = String(req.body.name || 'GitHub Actions').trim().slice(0, 100);
  const repository = String(req.body.repository || '').trim();
  const imageRepository = String(req.body.imageRepository || '').trim();
  const workflowFile = normalizeWorkflow(req.body.workflowFile);
  const branch = normalizeBranch(req.body.branch || 'main');
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) || !workflowFile || !branch ||
      !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/.test(imageRepository) || imageRepository.includes('@')) {
    return sendError(res, 400, 'Provide a GitHub repository, workflow YAML path, branch, and container image repository');
  }
  const lastSlash = imageRepository.lastIndexOf('/');
  if (imageRepository.lastIndexOf(':') > lastSlash) return sendError(res, 400, 'Use the image repository name without a tag');
  const token = randomToken();
  const id = crypto.randomUUID();
  const result = await pool.query(
    `INSERT INTO ci_integrations (id, project_id, name, repository, image_repository, workflow_file, branch, token_hash, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING id, name, repository, image_repository, workflow_file, branch, enabled, created_at`,
    [id, req.params.projectId, name, repository, imageRepository, workflowFile, branch, hash(token), req.user.id]
  );
  const snippet = [
    '- name: Create signed build provenance',
    '  env:',
    `    IMAGE_REPOSITORY: ${imageRepository}`,
    '    IMAGE_DIGEST: ${{ steps.push.outputs.digest }}',
    '  run: |',
    '    jq -n --arg image "$IMAGE_REPOSITORY" --arg repo "$GITHUB_REPOSITORY" --arg sha "$GITHUB_SHA" --arg ref "$GITHUB_REF" \'{imageRepository:$image,sourceRepository:$repo,commitSha:$sha,sourceRef:$ref}\' > provenance.json',
    '    cosign attest --yes --type custom --predicate provenance.json "$IMAGE_REPOSITORY@$IMAGE_DIGEST"',
    '- name: Register verified build with AttestGate',
    '  env:',
    '    ATTESTGATE_TOKEN: ${{ secrets.ATTESTGATE_TOKEN }}',
    `    IMAGE_REPOSITORY: ${imageRepository}`,
    '    IMAGE_DIGEST: ${{ steps.push.outputs.digest }}',
    '  run: |',
    `    PAYLOAD=$(jq -nc --arg image "$IMAGE_REPOSITORY" --arg digest "$IMAGE_DIGEST" --arg repo "$GITHUB_REPOSITORY" --arg sha "$GITHUB_SHA" --arg ref "$GITHUB_REF" '{imageRepository:$image,digest:$digest,sourceRepository:$repo,commitSha:$sha,sourceRef:$ref}')`,
    `    curl --fail-with-body -X POST "${APP_BASE_URL}/ci/${id}/artifacts" -H "Authorization: Bearer $ATTESTGATE_TOKEN" -H "Content-Type: application/json" -d "$PAYLOAD"`,
  ].join('\n');
  res.status(201).json({ integration: result.rows[0], token, workflowIdentity: identityFor(result.rows[0]), workflowSnippet: snippet });
}));

app.get('/api/projects/:projectId/integrations', requireUser, asyncRoute(async (req, res) => {
  if (!await projectRole(req.params.projectId, req.user.id)) return sendError(res, 404, 'Project not found');
  const result = await pool.query(
    `SELECT id, name, repository, image_repository, workflow_file, branch, enabled, created_at
       FROM ci_integrations WHERE project_id = $1 ORDER BY created_at DESC`, [req.params.projectId]
  );
  res.json({ integrations: result.rows });
}));

app.delete('/api/projects/:projectId/integrations/:integrationId', ...userMutation(async (req, res) => {
  const role = await projectRole(req.params.projectId, req.user.id);
  if (!hasRole(role, ['owner', 'admin'])) return sendError(res, role ? 403 : 404, 'Project administrator access required');
  const result = await pool.query(
    `UPDATE ci_integrations SET enabled = false WHERE id = $1 AND project_id = $2 RETURNING id`,
    [req.params.integrationId, req.params.projectId]
  );
  if (!result.rowCount) return sendError(res, 404, 'CI integration not found');
  res.json({ disabled: true });
}));

app.post('/api/projects/:projectId/clusters', ...userMutation(async (req, res) => {
  const role = await projectRole(req.params.projectId, req.user.id);
  if (!hasRole(role, ['owner', 'admin'])) return sendError(res, role ? 403 : 404, 'Project administrator access required');
  const name = String(req.body.name || '').trim();
  if (name.length < 2 || name.length > 100) return sendError(res, 400, 'Cluster name must be 2â€“100 characters');
  const token = randomToken();
  const id = crypto.randomUUID();
  try {
    await pool.query(
      `INSERT INTO clusters (id, project_id, name, token_hash, created_by) VALUES ($1, $2, $3, $4, $5)`,
      [id, req.params.projectId, name, hash(token), req.user.id]
    );
  } catch (error) {
    if (error.code === '23505') return sendError(res, 409, 'A cluster with that name is already enrolled');
    throw error;
  }
  res.status(201).json({
    cluster: { id, name, status: 'active', createdAt: new Date().toISOString() },
    token,
    install: {
      controlPlaneUrl: APP_BASE_URL,
      env: { CONTROL_PLANE_URL: APP_BASE_URL, CLUSTER_TOKEN: token },
      namespaceLabel: 'attestgate.io/enforce=true',
    },
  });
}));

app.get('/api/projects/:projectId/clusters', requireUser, asyncRoute(async (req, res) => {
  if (!await projectRole(req.params.projectId, req.user.id)) return sendError(res, 404, 'Project not found');
  const result = await pool.query(
    `SELECT id, name, status, last_seen_at, created_at FROM clusters WHERE project_id = $1 ORDER BY created_at DESC`, [req.params.projectId]
  );
  res.json({ clusters: result.rows });
}));

app.delete('/api/projects/:projectId/clusters/:clusterId', ...userMutation(async (req, res) => {
  const role = await projectRole(req.params.projectId, req.user.id);
  if (!hasRole(role, ['owner', 'admin'])) return sendError(res, role ? 403 : 404, 'Project administrator access required');
  const result = await pool.query(
    `UPDATE clusters SET status = 'revoked' WHERE id = $1 AND project_id = $2 RETURNING id`, [req.params.clusterId, req.params.projectId]
  );
  if (!result.rowCount) return sendError(res, 404, 'Cluster not found');
  res.json({ revoked: true });
}));

app.get('/api/projects/:projectId/artifacts', requireUser, asyncRoute(async (req, res) => {
  if (!await projectRole(req.params.projectId, req.user.id)) return sendError(res, 404, 'Project not found');
  const result = await pool.query(
    `SELECT id, image_repository, digest, source_repository, commit_sha, source_ref, workflow_identity, sbom_verified, verified_at
       FROM artifacts WHERE project_id = $1 ORDER BY verified_at DESC LIMIT 200`, [req.params.projectId]
  );
  res.json({ artifacts: result.rows });
}));

app.get('/api/projects/:projectId/decisions', requireUser, asyncRoute(async (req, res) => {
  if (!await projectRole(req.params.projectId, req.user.id)) return sendError(res, 404, 'Project not found');
  const result = await pool.query(
    `SELECT d.id, d.image_repository, d.digest, d.allowed, d.reason, d.namespace, d.workload, d.created_at, c.name AS cluster_name
       FROM admission_decisions d JOIN clusters c ON c.id = d.cluster_id
      WHERE d.project_id = $1 ORDER BY d.created_at DESC LIMIT 300`, [req.params.projectId]
  );
  res.json({ decisions: result.rows });
}));

app.post('/ci/:integrationId/artifacts', requireBearer, asyncRoute(async (req, res) => {
  if (!UUID.test(req.params.integrationId)) return sendError(res, 404, 'Integration not found');
  const integrationResult = await pool.query(
    `SELECT * FROM ci_integrations WHERE id = $1 AND token_hash = $2 AND enabled`, [req.params.integrationId, req.bearerHash]
  );
  const integration = integrationResult.rows[0];
  if (!integration) return sendError(res, 401, 'Invalid or disabled CI integration token');

  const imageRepository = String(req.body.imageRepository || '').trim();
  const digest = String(req.body.digest || '').trim();
  const sourceRepository = String(req.body.sourceRepository || '').trim();
  const commitSha = String(req.body.commitSha || '').trim().toLowerCase();
  const sourceRef = String(req.body.sourceRef || '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/.test(imageRepository) || imageRepository.includes('@') || !SHA256.test(digest)) {
    return sendError(res, 400, 'Provide an image repository and canonical sha256 digest');
  }
  const lastSlash = imageRepository.lastIndexOf('/');
  if (imageRepository.lastIndexOf(':') > lastSlash) return sendError(res, 400, 'Use the repository name without an image tag');
  if (imageRepository !== integration.image_repository || sourceRepository !== integration.repository ||
      sourceRef !== `refs/heads/${integration.branch}` || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(commitSha)) {
    return sendError(res, 403, 'Build image, source repository, commit, or branch does not match this integration');
  }
  const workflowIdentity = identityFor(integration);
  const [signature, sbom, provenance] = await Promise.all([
    verifier.verifySignatureAsync(imageRepository, digest, COSIGN_TIMEOUT_MS, workflowIdentity),
    verifier.verifySBOMAsync(imageRepository, digest, COSIGN_TIMEOUT_MS, workflowIdentity),
    verifier.verifyProvenanceAsync(imageRepository, digest, COSIGN_TIMEOUT_MS, workflowIdentity, {
      imageRepository, sourceRepository, commitSha, sourceRef,
    }),
  ]);
  if (!signature.valid || !sbom.valid || !provenance.valid) {
    return res.status(422).json({
      error: 'Build attestation verification failed',
      checks: { signature: signature.valid, sbom: sbom.valid, provenance: provenance.valid },
      details: { signature: signature.error, sbom: sbom.error, provenance: provenance.error },
    });
  }

  const artifact = await pool.query(
    `INSERT INTO artifacts (id, project_id, integration_id, image_repository, digest, source_repository, commit_sha, source_ref, workflow_identity, sbom_verified)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)
     ON CONFLICT (project_id, integration_id, image_repository, digest) DO UPDATE SET
       integration_id = EXCLUDED.integration_id, source_repository = EXCLUDED.source_repository,
       commit_sha = EXCLUDED.commit_sha, source_ref = EXCLUDED.source_ref,
       workflow_identity = EXCLUDED.workflow_identity, sbom_verified = true, verified_at = now()
     RETURNING id, image_repository, digest, source_repository, commit_sha, source_ref, workflow_identity, sbom_verified, verified_at`,
    [crypto.randomUUID(), integration.project_id, integration.id, imageRepository, digest, sourceRepository, commitSha, sourceRef, workflowIdentity]
  );
  res.status(201).json({ artifact: artifact.rows[0], verified: true });
}));

app.post('/v1/admission/verify', requireBearer, asyncRoute(async (req, res) => {
  const clusterResult = await pool.query(
    `SELECT id, project_id FROM clusters WHERE token_hash = $1 AND status = 'active'`, [req.bearerHash]
  );
  const cluster = clusterResult.rows[0];
  if (!cluster) return sendError(res, 401, 'Invalid or revoked cluster token');
  const parsed = parseImageReference(req.body.image);
  const namespace = String(req.body.namespace || '').slice(0, 253);
  const workload = String(req.body.workload || '').slice(0, 253);
  let allowed = false;
  let reason = 'Image must be pinned by its sha256 digest';
  let artifact = null;
  if (parsed) {
    const result = await pool.query(
      `SELECT image_repository, digest, source_repository, commit_sha, source_ref, workflow_identity, verified_at
         FROM artifacts WHERE project_id = $1 AND image_repository = $2 AND digest = $3 AND sbom_verified
         ORDER BY verified_at DESC LIMIT 1`,
      [cluster.project_id, parsed.repository, parsed.digest]
    );
    artifact = result.rows[0] || null;
    allowed = Boolean(artifact);
    reason = allowed ? 'verified_artifact' : 'no verified CI artifact exists for this image digest';
  }
  await pool.query(
    `INSERT INTO admission_decisions (id, project_id, cluster_id, image_repository, digest, allowed, reason, namespace, workload)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [crypto.randomUUID(), cluster.project_id, cluster.id, parsed?.repository || String(req.body.image || '').slice(0, 255), parsed?.digest || null, allowed, reason, namespace, workload]
  );
  await pool.query('UPDATE clusters SET last_seen_at = now() WHERE id = $1', [cluster.id]);
  res.json({ allowed, reason, artifact });
}));

app.use((error, _req, res, _next) => {
  console.error('[request]', error.message);
  if (res.headersSent) return;
  if (error.code === '23505') return sendError(res, 409, 'A record with those details already exists');
  res.status(500).json({ error: 'Internal server error' });
});

async function start() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  if (!process.env.GITHUB_OAUTH_CLIENT_ID || !process.env.GITHUB_OAUTH_CLIENT_SECRET) {
    throw new Error('GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET are required');
  }
  let baseUrl;
  try { baseUrl = new URL(APP_BASE_URL); } catch { throw new Error('APP_BASE_URL must be an absolute URL'); }
  if (!['http:', 'https:'].includes(baseUrl.protocol) ||
      (baseUrl.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(baseUrl.hostname))) {
    throw new Error('APP_BASE_URL must use HTTPS except for local development');
  }
  if (baseUrl.protocol === 'https:' && !COOKIE_SECURE) throw new Error('Set COOKIE_SECURE=true when APP_BASE_URL uses HTTPS');
  if (!Number.isInteger(COSIGN_TIMEOUT_MS) || COSIGN_TIMEOUT_MS < 100 || COSIGN_TIMEOUT_MS > 60_000) {
    throw new Error('COSIGN_TIMEOUT_MS must be an integer between 100 and 60000');
  }
  await migrate();
  const server = app.listen(PORT, '0.0.0.0', () => console.log(`AttestGate control plane listening on ${PORT}`));
  const shutdown = async () => {
    server.close(async () => { await pool.end(); process.exit(0); });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
  return server;
}

if (require.main === module) {
  start().catch(error => {
    console.error(`[startup] ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { app, start, parseImageReference, slugify, normalizeWorkflow, normalizeBranch };

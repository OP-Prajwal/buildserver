'use strict';

const app = document.getElementById('app');
const loginPanel = document.getElementById('loginPanel');
const workspace = document.getElementById('workspace');
const projectList = document.getElementById('projectList');
const projectView = document.getElementById('projectView');
const emptyState = document.getElementById('emptyState');
const projectContent = document.getElementById('projectContent');
const projectDialog = document.getElementById('projectDialog');
const notice = document.getElementById('notice');

let currentUser = null;
let currentProject = null;
let csrfToken = '';
let activeTab = 'overview';
let loaded = {};
let demoDecisions = [];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

function showNotice(message, error = false) {
  notice.textContent = message;
  notice.classList.toggle('error', error);
  notice.classList.remove('hidden');
  clearTimeout(showNotice.timer);
  showNotice.timer = setTimeout(() => notice.classList.add('hidden'), 5200);
}

async function request(url, options = {}) {
  const headers = new Headers(options.headers || {});
  const method = (options.method || 'GET').toUpperCase();
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(url, { ...options, method, headers, credentials: 'same-origin' });
  const payload = response.status === 204 ? {} : await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function isAdmin() {
  return ['owner', 'admin'].includes(currentProject?.role);
}

function setAccount() {
  const account = document.getElementById('account');
  if (!currentUser) { account.replaceChildren(); return; }
  account.innerHTML = `<span>${escapeHtml(currentUser.displayName)} <span class="muted">@${escapeHtml(currentUser.githubLogin)}</span></span><button class="button" data-action="logout">Sign out</button>`;
}

async function boot() {
  const hashParams = new URLSearchParams(location.hash.slice(1));
  const invite = hashParams.get('invite');
  if (invite) {
    sessionStorage.setItem('attestgate_invite', invite);
    history.replaceState(null, '', location.pathname + location.search);
  }
  try {
    const result = await request('/api/me');
    currentUser = result.user;
    csrfToken = result.csrfToken || '';
    loginPanel.classList.add('hidden');
    workspace.classList.remove('hidden');
    setAccount();
    if (sessionStorage.getItem('attestgate_invite')) {
      try { await acceptPendingInvite(); }
      catch (error) { showNotice(error.message, true); }
    }
    await loadProjects();
  } catch {
    workspace.classList.add('hidden');
    loginPanel.classList.remove('hidden');
    document.getElementById('account').innerHTML = '<a class="button" href="/auth/github">Sign in</a>';
    if (sessionStorage.getItem('attestgate_invite')) {
      const p = document.createElement('p');
      p.className = 'muted';
      p.textContent = 'Sign in with the GitHub account that has the invited email address to accept your project invitation.';
      loginPanel.appendChild(p);
    }
  }
}

async function acceptPendingInvite() {
  const token = sessionStorage.getItem('attestgate_invite');
  if (!token) return;
  const result = await request('/api/invitations/accept', { method: 'POST', body: JSON.stringify({ token }) });
  sessionStorage.removeItem('attestgate_invite');
  showNotice(`Joined project as ${result.role}.`);
}

async function loadProjects(preferredId) {
  const result = await request('/api/projects');
  const projects = result.projects;
  if (!projects.length) {
    currentProject = null;
    projectList.innerHTML = '';
    projectView.classList.add('hidden');
    emptyState.classList.remove('hidden');
    return;
  }
  projectList.innerHTML = projects.map(project => `
    <button class="project-choice ${currentProject?.id === project.id ? 'active' : ''}" data-action="select-project" data-id="${escapeHtml(project.id)}">
      ${escapeHtml(project.name)}<small>${escapeHtml(project.role)} · ${project.cluster_count} clusters</small>
    </button>`).join('');
  const selected = projects.find(project => project.id === (preferredId || currentProject?.id)) || projects[0];
  await selectProject(selected.id);
}

async function selectProject(projectId) {
  const result = await request(`/api/projects/${encodeURIComponent(projectId)}`);
  currentProject = result.project;
  activeTab = 'overview';
  loaded = {};
  demoDecisions = [];
  emptyState.classList.add('hidden');
  projectView.classList.remove('hidden');
  document.getElementById('projectName').textContent = currentProject.name;
  document.getElementById('projectSlug').textContent = `PROJECT / ${currentProject.slug}`;
  document.getElementById('projectRole').textContent = currentProject.role;
  projectList.querySelectorAll('.project-choice').forEach(button => button.classList.toggle('active', button.dataset.id === currentProject.id));
  document.querySelectorAll('.tab').forEach(button => button.classList.toggle('active', button.dataset.tab === activeTab));
  await loadTab();
}

async function loadTab() {
  if (!currentProject) return;
  const projectId = encodeURIComponent(currentProject.id);
  const common = [
    request(`/api/projects/${projectId}/members`).then(r => loaded.members = r.members),
    request(`/api/projects/${projectId}/integrations`).then(r => loaded.integrations = r.integrations),
    request(`/api/projects/${projectId}/clusters`).then(r => loaded.clusters = r.clusters),
    request(`/api/projects/${projectId}/artifacts`).then(r => loaded.artifacts = r.artifacts),
    request(`/api/projects/${projectId}/decisions`).then(r => loaded.decisions = r.decisions),
  ];
  if (isAdmin()) common.push(request(`/api/projects/${projectId}/invitations`).then(r => loaded.invitations = r.invitations));
  await Promise.all(common);
  renderTab();
}

function renderTab() {
  const projectId = escapeHtml(currentProject.id);
  if (activeTab === 'overview') {
    projectContent.innerHTML = `
      <div class="metric-grid">
        <div class="metric"><strong>${loaded.members?.length || 0}</strong><span>Project members</span></div>
        <div class="metric"><strong>${loaded.integrations?.length || 0}</strong><span>CI integrations</span></div>
        <div class="metric"><strong>${loaded.clusters?.filter(c => c.status === 'active').length || 0}</strong><span>Active clusters</span></div>
        <div class="metric"><strong>${loaded.artifacts?.length || 0}</strong><span>Verified image digests</span></div>
      </div>
      <div class="grid-two">
        <section class="panel"><p class="eyebrow">01 / TEAM</p><h2>Invite the engineers</h2><p>Invite each person by their verified GitHub email and assign a project role. Invitation links expire after seven days and work once.</p><button class="button" data-tab-link="team">Manage team</button></section>
        <section class="panel"><p class="eyebrow">02 / CI</p><h2>Register verified builds</h2><p>AttestGate checks the CI workflow identity and SPDX SBOM before it records a digest as deployable.</p><button class="button" data-tab-link="ci">Connect CI</button></section>
        <section class="panel"><p class="eyebrow">03 / CLUSTER</p><h2>Enroll Kubernetes</h2><p>Each cluster receives a project-scoped credential. The admission controller checks every image against this project's verified artifact records.</p><button class="button" data-tab-link="clusters">Enroll a cluster</button></section>
        <section class="panel"><p class="eyebrow">04 / AUDIT</p><h2>Review actual decisions</h2><p>See the source commit for each verified image and the allow or deny decision returned to each cluster.</p><button class="button" data-tab-link="activity">View activity</button></section>
      </div>`;
    return;
  }
  if (activeTab === 'team') renderTeam(projectId);
  if (activeTab === 'ci') renderIntegrations(projectId);
  if (activeTab === 'clusters') renderClusters(projectId);
  if (activeTab === 'activity') renderActivity();
}

function table(headers, rows, emptyMessage) {
  if (!rows.length) return `<div class="panel"><p class="empty-row">${escapeHtml(emptyMessage)}</p></div>`;
  return `<div class="panel table-wrap"><table><thead><tr>${headers.map(h => `<th>${escapeHtml(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}

function renderTeam(projectId) {
  const inviteForm = isAdmin() ? `
    <section class="panel"><h2>Invite an engineer</h2><p>AttestGate creates a single-use link tied to this email. The invited person signs in with GitHub and must have this verified email on their account.</p>
      <form data-form="invite"><div class="form-row"><label>Email address<input name="email" type="email" autocomplete="email" required placeholder="engineer@company.com"></label><label>Project role<select name="role"><option value="engineer">Engineer</option><option value="viewer">Viewer</option>${currentProject.role === 'owner' ? '<option value="admin">Project admin</option>' : ''}</select></label></div><button class="button primary">Create invitation link</button></form>
      <div id="inviteResult"></div>
    </section>` : '';
  const memberRows = (loaded.members || []).map(member => {
    const canManage = isAdmin() && member.role !== 'owner' && (currentProject.role === 'owner' || member.role !== 'admin');
    const roleCell = canManage
      ? `<select data-member-role data-id="${escapeHtml(member.id)}">${currentProject.role === 'owner' ? `<option value="admin" ${member.role === 'admin' ? 'selected' : ''}>Admin</option>` : ''}<option value="engineer" ${member.role === 'engineer' ? 'selected' : ''}>Engineer</option><option value="viewer" ${member.role === 'viewer' ? 'selected' : ''}>Viewer</option></select><button class="button" data-action="save-member-role" data-id="${escapeHtml(member.id)}">Save</button>`
      : escapeHtml(member.role);
    const remove = canManage ? `<button class="button danger" data-action="remove-member" data-id="${escapeHtml(member.id)}">Remove</button>` : '';
    return `<tr><td><strong>${escapeHtml(member.display_name)}</strong><br><span class="muted">@${escapeHtml(member.github_login)} · ${escapeHtml(member.email)}</span></td><td>${roleCell}</td><td>${new Date(member.joined_at).toLocaleDateString()}</td><td>${remove}</td></tr>`;
  });
  const inviteRows = (loaded.invitations || []).map(inv => `<tr><td>${escapeHtml(inv.email)}</td><td>${escapeHtml(inv.role)}</td><td>${inv.accepted_at ? 'Accepted' : inv.revoked_at ? 'Revoked' : new Date(inv.expires_at) < new Date() ? 'Expired' : 'Pending'}</td><td>${!inv.accepted_at && !inv.revoked_at && isAdmin() ? `<button class="button danger" data-action="revoke-invite" data-id="${escapeHtml(inv.id)}">Revoke</button>` : ''}</td></tr>`);
  projectContent.innerHTML = `<section class="panel"><h2>Project members</h2>${table(['Engineer', 'Role', 'Joined', ''], memberRows, 'No members yet.')}</section>${inviteForm}${isAdmin() ? `<section class="panel"><h2>Invitations</h2>${table(['Email', 'Role', 'Status', ''], inviteRows, 'No invitations have been created.')}</section>` : ''}`;
}

function renderIntegrations(projectId) {
  const form = isAdmin() ? `
    <section class="panel"><h2>Connect a GitHub Actions workflow</h2><p>Create an integration for the exact source repository, protected branch, signing workflow, and container repository. Its token is shown once.</p>
      <form data-form="integration"><div class="form-row"><label>Integration name<input name="name" required value="GitHub Actions"></label><label>GitHub repository<input name="repository" required placeholder="acme/payments-api"></label></div><div class="form-row"><label>Workflow file<input name="workflowFile" required placeholder=".github/workflows/release.yml"></label><label>Protected branch<input name="branch" required value="main"></label></div><label>Container image repository<input name="imageRepository" required placeholder="ghcr.io/acme/payments-api"><span class="field-note">Use the exact repository without a tag.</span></label><button class="button primary">Create CI integration</button></form><div id="integrationResult"></div>
    </section>` : '';
  const rows = (loaded.integrations || []).map(item => `<tr><td>${escapeHtml(item.name)}</td><td><code>${escapeHtml(item.repository)}</code><br><span class="muted">${escapeHtml(item.workflow_file)} @ ${escapeHtml(item.branch)}</span></td><td><code>${escapeHtml(item.image_repository)}</code></td><td>${item.enabled ? 'Active' : 'Disabled'}</td><td>${item.enabled && isAdmin() ? `<button class="button danger" data-action="disable-integration" data-id="${escapeHtml(item.id)}">Disable</button>` : ''}</td></tr>`);
  projectContent.innerHTML = `${form}<section class="panel"><h2>Configured integrations</h2>${table(['Name', 'Trusted source', 'Image repository', 'Status', ''], rows, 'No CI workflow connected yet.')}</section>`;
}

function renderClusters(projectId) {
  const form = isAdmin() ? `
    <section class="panel"><h2>Enroll a Kubernetes cluster</h2><p>AttestGate creates a one-time, project-scoped token. Store it as a Kubernetes Secret and configure the admission controller with the control plane URL.</p><form data-form="cluster"><label>Cluster name<input name="name" required minlength="2" maxlength="100" placeholder="production-us-east"></label><button class="button primary">Create cluster credential</button></form><div id="clusterResult"></div></section>` : '';
  const rows = (loaded.clusters || []).map(cluster => `<tr><td>${escapeHtml(cluster.name)}</td><td><span class="status-pill">${escapeHtml(cluster.status)}</span></td><td>${cluster.last_seen_at ? new Date(cluster.last_seen_at).toLocaleString() : 'Waiting for first admission request'}</td><td>${cluster.status === 'active' && isAdmin() ? `<button class="button danger" data-action="revoke-cluster" data-id="${escapeHtml(cluster.id)}">Revoke token</button>` : ''}</td></tr>`);
  projectContent.innerHTML = `${form}<section class="panel"><h2>Enrolled clusters</h2>${table(['Cluster', 'Status', 'Last seen', ''], rows, 'No clusters enrolled yet.')}</section>`;
}

function renderActivity() {
  const artifactRows = (loaded.artifacts || []).map(item => `<tr><td><code>${escapeHtml(item.image_repository)}@${escapeHtml(item.digest)}</code></td><td><code>${escapeHtml(item.commit_sha.slice(0, 12))}</code><br><span class="muted">${escapeHtml(item.source_repository)} · ${escapeHtml(item.source_ref)}</span></td><td>${new Date(item.verified_at).toLocaleString()}</td></tr>`);
  const decisionRows = (loaded.decisions || []).map(item => `<tr><td><span class="${item.allowed ? 'status-allowed' : 'status-denied'}">${item.allowed ? 'Allowed' : 'Denied'}</span><br><span class="muted">${escapeHtml(item.reason)}</span></td><td><code>${escapeHtml(item.image_repository)}${item.digest ? `@${escapeHtml(item.digest)}` : ''}</code></td><td>${escapeHtml(item.cluster_name)}<br><span class="muted">${escapeHtml(item.namespace || '')} ${escapeHtml(item.workload || '')}</span></td><td>${new Date(item.created_at).toLocaleString()}</td></tr>`);
  const demoRows = demoDecisions.map(item => `<tr><td><span class="${item.allowed ? 'status-allowed' : 'status-denied'}">${item.allowed ? 'Allowed' : 'Denied'}</span><br><span class="demo-tag">SIMULATED</span><br><span class="muted">${escapeHtml(item.reason)}</span></td><td><code>${escapeHtml(item.image)}</code></td><td>${escapeHtml(item.cluster)}<br><span class="muted">${escapeHtml(item.namespace)} · ${escapeHtml(item.workload)}</span></td><td>${escapeHtml(item.time)}</td></tr>`);
  const demoPanel = `<section class="panel demo-panel"><div class="panel-heading"><div><p class="eyebrow">PRESENTATION MODE</p><h2>Simulate an admission check</h2></div><span class="demo-tag">SIMULATION</span></div><p>Runs a local walkthrough using this project’s verified digest. No Kubernetes request is sent, and these results are not added to the audit log.</p><button class="button primary" data-action="simulate-admission" ${loaded.artifacts?.length ? '' : 'disabled'}>Run allow and deny scenario</button>${demoRows.length ? table(['Simulated decision', 'Image', 'Cluster and workload', 'Time'], demoRows, '') : ''}</section>`;
  projectContent.innerHTML = `${demoPanel}<section class="panel"><h2>Verified build artifacts</h2><p>Only artifacts whose image signature and SBOM attestation passed verification appear here.</p>${table(['Image digest', 'Source', 'Verified'], artifactRows, 'No CI builds have been registered.')}</section><section class="panel"><h2>Kubernetes admission decisions</h2>${table(['Decision', 'Image', 'Cluster and workload', 'Time'], decisionRows, 'No admission requests have been recorded.')}</section>`;
}

function formObject(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function showSecretBlock(target, title, secret, instructions) {
  const element = document.getElementById(target);
  element.innerHTML = `<div class="panel"><p class="eyebrow">${escapeHtml(title)}</p><div class="token-box">${escapeHtml(secret)}</div><pre>${escapeHtml(instructions)}</pre><div class="inline-actions"><button class="button" data-action="copy" data-copy="${escapeHtml(secret)}">Copy credential</button><button class="button" data-action="copy" data-copy="${escapeHtml(instructions)}">Copy setup</button></div></div>`;
}

document.addEventListener('click', async event => {
  const tabButton = event.target.closest('[data-tab]');
  if (tabButton) {
    activeTab = tabButton.dataset.tab;
    document.querySelectorAll('.tab').forEach(button => button.classList.toggle('active', button === tabButton));
    await loadTab();
    return;
  }
  const tabLink = event.target.closest('[data-tab-link]');
  if (tabLink) {
    activeTab = tabLink.dataset.tabLink;
    document.querySelectorAll('.tab').forEach(button => button.classList.toggle('active', button.dataset.tab === activeTab));
    await loadTab();
    return;
  }
  const button = event.target.closest('[data-action]');
  if (!button) return;
  try {
    switch (button.dataset.action) {
      case 'new-project':
        document.getElementById('projectForm').reset();
        projectDialog.showModal();
        break;
      case 'select-project':
        await selectProject(button.dataset.id);
        break;
      case 'logout':
        await request('/auth/logout', { method: 'POST' });
        location.reload();
        break;
      case 'copy':
        await navigator.clipboard.writeText(button.dataset.copy || '');
        showNotice('Copied. Store the credential in your secret manager.');
        break;
      case 'simulate-admission': {
        const artifact = loaded.artifacts?.[0];
        if (!artifact) { showNotice('Register a verified build before running this scenario.', true); break; }
        const cluster = loaded.clusters?.find(item => item.status === 'active')?.name || 'presentation-cluster';
        const time = new Date().toLocaleString();
        const deniedDigest = `sha256:${'0'.repeat(64)}`;
        demoDecisions = [
          { allowed: true, image: `${artifact.image_repository}@${artifact.digest}`, cluster, namespace: 'demo', workload: 'payments-demo', reason: 'Exact digest exists in this project’s verified CI artifacts', time },
          { allowed: false, image: `${artifact.image_repository}@${deniedDigest}`, cluster, namespace: 'demo', workload: 'untrusted-demo', reason: 'No verified CI artifact exists for this digest', time },
        ];
        renderActivity();
        showNotice('Simulation complete. These results were not sent to Kubernetes or stored in the audit log.');
        break;
      }
      case 'revoke-invite':
        if (confirm('Revoke this pending invitation?')) {
          await request(`/api/projects/${currentProject.id}/invitations/${button.dataset.id}`, { method: 'DELETE' });
          await loadTab(); showNotice('Invitation revoked.');
        }
        break;
      case 'revoke-cluster':
        if (confirm('Revoke this cluster token? Its admission controller will fail closed.')) {
          await request(`/api/projects/${currentProject.id}/clusters/${button.dataset.id}`, { method: 'DELETE' });
          await loadTab(); showNotice('Cluster token revoked.');
        }
        break;
      case 'disable-integration':
        if (confirm('Disable this CI token? Future build registrations will be rejected.')) {
          await request(`/api/projects/${currentProject.id}/integrations/${button.dataset.id}`, { method: 'DELETE' });
          await loadTab(); showNotice('CI integration disabled.');
        }
        break;
      case 'save-member-role': {
        const select = [...projectContent.querySelectorAll('[data-member-role]')].find(item => item.dataset.id === button.dataset.id);
        if (!select) break;
        await request(`/api/projects/${currentProject.id}/members/${button.dataset.id}`, { method: 'PATCH', body: JSON.stringify({ role: select.value }) });
        await loadTab(); showNotice('Project role updated.');
        break;
      }
      case 'remove-member':
        if (confirm('Remove this person from the project?')) {
          await request(`/api/projects/${currentProject.id}/members/${button.dataset.id}`, { method: 'DELETE' });
          await loadTab(); showNotice('Project member removed.');
        }
        break;
    }
  } catch (error) { showNotice(error.message, true); }
});

document.addEventListener('submit', async event => {
  const form = event.target;
  if (form.id === 'projectForm') {
    if (event.submitter?.value === 'cancel') return;
    event.preventDefault();
    try {
      const payload = formObject(form);
      const result = await request('/api/projects', { method: 'POST', body: JSON.stringify(payload) });
      projectDialog.close();
      await loadProjects(result.project.id);
      showNotice('Project created. Invite your team to continue.');
    } catch (error) { showNotice(error.message, true); }
    return;
  }
  const type = form.dataset.form;
  if (!type) return;
  event.preventDefault();
  const button = form.querySelector('button[type="submit"],button:not([type])');
  if (button) button.disabled = true;
  try {
    const payload = formObject(form);
    const base = `/api/projects/${currentProject.id}`;
    if (type === 'invite') {
      const result = await request(`${base}/invitations`, { method: 'POST', body: JSON.stringify(payload) });
      await loadTab();
      const target = document.getElementById('inviteResult');
      target.innerHTML = `<div class="token-box">Invitation URL: <a class="invite-url" href="${escapeHtml(result.inviteUrl)}">${escapeHtml(result.inviteUrl)}</a></div><p class="field-note">This link is shown once. Send it to the invited engineer; it expires in seven days.</p>`;
      form.reset();
    } else if (type === 'integration') {
      const result = await request(`${base}/integrations`, { method: 'POST', body: JSON.stringify(payload) });
      await loadTab();
      showSecretBlock('integrationResult', 'Copy this token into the GitHub repository secret ATTESTGATE_TOKEN', result.token, result.workflowSnippet);
      const identity = document.createElement('p');
      identity.className = 'field-note';
      identity.textContent = `Expected signing identity: ${result.workflowIdentity}`;
      document.getElementById('integrationResult').append(identity);
      form.reset();
    } else if (type === 'cluster') {
      const result = await request(`${base}/clusters`, { method: 'POST', body: JSON.stringify(payload) });
      await loadTab();
      const command = `kubectl -n attestgate-system create secret generic attestgate-cluster-auth --from-literal=token='${result.token}'\n\nSet CONTROL_PLANE_URL=${result.install.controlPlaneUrl} on the admission controller, then label a namespace: kubectl label namespace production ${result.install.namespaceLabel}`;
      showSecretBlock('clusterResult', 'Copy this cluster token into the admission controller Secret', result.token, command);
      form.reset();
    }
    showNotice('Saved.');
  } catch (error) { showNotice(error.message, true); }
  finally { if (button) button.disabled = false; }
});

boot().catch(error => showNotice(error.message, true));

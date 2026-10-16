CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  github_id BIGINT NOT NULL UNIQUE,
  github_login TEXT NOT NULL,
  display_name TEXT NOT NULL,
  email TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash CHAR(64) PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_hash CHAR(64) NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 2 AND 100),
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project_members (
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'engineer', 'viewer')),
  joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (project_id, user_id)
);

CREATE TABLE IF NOT EXISTS invitations (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'engineer', 'viewer')),
  token_hash CHAR(64) NOT NULL UNIQUE,
  invited_by UUID NOT NULL REFERENCES users(id),
  expires_at TIMESTAMPTZ NOT NULL,
  accepted_by UUID REFERENCES users(id),
  accepted_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS invitations_project_idx ON invitations(project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ci_integrations (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  repository TEXT NOT NULL,
  image_repository TEXT NOT NULL,
  workflow_file TEXT NOT NULL,
  branch TEXT NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clusters (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  last_seen_at TIMESTAMPTZ,
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS clusters_active_name_idx ON clusters(project_id, name) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS artifacts (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  integration_id UUID NOT NULL REFERENCES ci_integrations(id) ON DELETE RESTRICT,
  image_repository TEXT NOT NULL,
  digest TEXT NOT NULL CHECK (digest ~ '^sha256:[a-f0-9]{64}$'),
  source_repository TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  workflow_identity TEXT NOT NULL,
  sbom_verified BOOLEAN NOT NULL DEFAULT true,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, integration_id, image_repository, digest)
);
CREATE INDEX IF NOT EXISTS artifacts_project_verified_idx ON artifacts(project_id, verified_at DESC);

CREATE TABLE IF NOT EXISTS admission_decisions (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  cluster_id UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  image_repository TEXT NOT NULL,
  digest TEXT,
  allowed BOOLEAN NOT NULL,
  reason TEXT NOT NULL,
  namespace TEXT,
  workload TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS admission_project_created_idx ON admission_decisions(project_id, created_at DESC);

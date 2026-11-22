-- Spike for checklist row P0-19 (docs/governance.md Section 8): the tenancy, row-level security
-- and immutability parts of docs/data-model.md, made runnable. NOT the product migration (WP-1.5).
-- Run as a superuser or the migration role on an empty database.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_role') THEN
    CREATE ROLE app_role NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
    CREATE ROLE audit_writer NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;

CREATE FUNCTION forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% on % is not allowed (immutable table)', TG_OP, TG_TABLE_NAME
    USING ERRCODE = 'integrity_constraint_violation';
END $$;

-- The tenant of the current transaction. Unset or empty means NULL, which matches no row (fail closed).
CREATE FUNCTION current_tenant() RETURNS uuid LANGUAGE sql STABLE AS
  $$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;

CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  external_subject text NOT NULL,
  display_name text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, external_subject)
);

CREATE TABLE agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  name text NOT NULL,
  owner_user_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'suspended', 'retired')),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  FOREIGN KEY (tenant_id, owner_user_id) REFERENCES users (tenant_id, id)
);

CREATE TABLE mcp_servers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  namespace text NOT NULL,
  url text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'quarantined', 'retired')),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, namespace)
);

CREATE TABLE tools (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  server_id uuid NOT NULL,
  name text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'quarantined', 'rejected')),
  action_class text NOT NULL CHECK (action_class IN ('read', 'write', 'execute', 'delete')),
  UNIQUE (tenant_id, id),
  UNIQUE (server_id, name),
  FOREIGN KEY (tenant_id, server_id) REFERENCES mcp_servers (tenant_id, id)
);

CREATE TABLE tool_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  tool_id uuid NOT NULL,
  version_no int NOT NULL,
  canonical_json jsonb NOT NULL,
  sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
  approved_by uuid NOT NULL,
  approved_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tool_id, version_no),
  UNIQUE (tool_id, sha256),
  FOREIGN KEY (tenant_id, tool_id) REFERENCES tools (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_by) REFERENCES users (tenant_id, id)
);

CREATE TABLE approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  subject_type text NOT NULL CHECK (subject_type IN ('tool_version', 'agent', 'grant', 'call')),
  subject_id uuid NOT NULL,
  requested_by uuid NOT NULL,
  decided_by uuid,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES users (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES users (tenant_id, id),
  CONSTRAINT approvals_sod CHECK (decided_by IS NULL OR decided_by <> requested_by)
);

CREATE TABLE permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  agent_id uuid NOT NULL,
  tool_id uuid NOT NULL,
  action_classes text[] NOT NULL,
  resource_pattern text NOT NULL DEFAULT '*',
  grant_type text NOT NULL CHECK (grant_type IN ('static', 'jit')),
  expires_at timestamptz,
  requested_by uuid NOT NULL,
  approved_by uuid NOT NULL,
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
  FOREIGN KEY (tenant_id, tool_id) REFERENCES tools (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES users (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_by) REFERENCES users (tenant_id, id),
  CONSTRAINT permissions_jit_expiry CHECK (grant_type <> 'jit' OR expires_at IS NOT NULL),
  CONSTRAINT permissions_sod CHECK (requested_by <> approved_by)
);

CREATE TABLE scan_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  server_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('import', 'rescan')),
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'claimed', 'done', 'failed')),
  claimed_by text,
  lease_expires_at timestamptz,
  attempts int NOT NULL DEFAULT 0,
  max_attempts int NOT NULL DEFAULT 3,
  FOREIGN KEY (tenant_id, server_id) REFERENCES mcp_servers (tenant_id, id)
);

CREATE TABLE audit_events (
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  seq bigint NOT NULL,
  event_id uuid NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  event_type text NOT NULL,
  actor text NOT NULL,
  decision text,
  policy_hash bytea,
  input_digest bytea,
  prev_hash bytea NOT NULL,
  hash bytea NOT NULL,
  PRIMARY KEY (tenant_id, seq),
  UNIQUE (tenant_id, event_id)
);

-- Immutability for everyone, the table owner included (privileges alone do not bind the owner).
CREATE TRIGGER tool_versions_immutable BEFORE UPDATE OR DELETE ON tool_versions
  FOR EACH ROW EXECUTE FUNCTION forbid_change();
CREATE TRIGGER tool_versions_no_truncate BEFORE TRUNCATE ON tool_versions
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_change();
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION forbid_change();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_change();

-- Row-level security on every tenant-scoped table, forced so the owner is bound too.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','agents','mcp_servers','tools','tool_versions','approvals','permissions','scan_jobs','audit_events']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', t);
  END LOOP;
END $$;

-- tenants is not tenant-scoped: an application session sees only its own row and cannot write.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY own_tenant ON tenants FOR SELECT USING (id = current_tenant());

GRANT USAGE ON SCHEMA public TO app_role, audit_writer;
GRANT SELECT ON tenants TO app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, agents, mcp_servers, tools, approvals, permissions, scan_jobs TO app_role;
GRANT SELECT, INSERT ON tool_versions TO app_role;
GRANT SELECT, INSERT ON audit_events TO app_role, audit_writer;
GRANT EXECUTE ON FUNCTION current_tenant() TO app_role, audit_writer;

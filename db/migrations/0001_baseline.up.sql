-- WP-1.5 baseline schema (docs/data-model.md Section 3), Phase 1 scope.
-- Run by the migration owner on an empty database. Rules (data-model Section 5):
--   * tenant_id on every tenant-owned row, unique (tenant_id, id), composite foreign keys
--   * row-level security enabled AND forced, USING and WITH CHECK on current_tenant()
--   * tool_versions and audit_events are immutable for everyone, owner included
--   * the audit chain is written only by audit_writer; the API goes through the outbox
-- Tenancy is ADR-4 (proposed): shared multi-tenant with row-level security.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_role') THEN
    CREATE ROLE app_role NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
    CREATE ROLE audit_writer NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'readonly_reporting') THEN
    CREATE ROLE readonly_reporting NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

CREATE FUNCTION forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% on % is not allowed (immutable table)', TG_OP, TG_TABLE_NAME
    USING ERRCODE = 'integrity_constraint_violation';
END $$;

-- Tenant of the current transaction; unset or empty is NULL, which matches no row (fail closed).
-- The application sets it with set_config('app.tenant_id', <id>, true) inside the request transaction.
CREATE FUNCTION current_tenant() RETURNS uuid LANGUAGE sql STABLE AS
  $$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;

-- ------------------------------------------------------------------ 3.1 tenancy and access
CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  region text,
  data_residency text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  external_subject text NOT NULL,
  display_name text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, external_subject)
);

CREATE TABLE role_bindings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  user_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('viewer','agent_owner','server_owner','security_engineer','approver',
                                     'security_admin','auditor','incident_responder','platform_operator')),
  scope_type text NOT NULL DEFAULT 'tenant' CHECK (scope_type IN ('tenant', 'agent', 'server')),
  scope_id uuid,
  expires_at timestamptz,
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id),
  FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id),
  CONSTRAINT role_bindings_scope CHECK ((scope_type = 'tenant') = (scope_id IS NULL))
);

CREATE TABLE classification_levels (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  name text NOT NULL,
  rank int NOT NULL CHECK (rank >= 0),
  description text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, rank),
  UNIQUE (tenant_id, name)
);

-- ------------------------------------------------------------------ 3.2 inventory
CREATE TABLE models (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  provider text NOT NULL,
  identifier text NOT NULL,
  version text NOT NULL,
  endpoint_ref text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'retired')),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, provider, identifier, version)
);

CREATE TABLE agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  name text NOT NULL,
  owner_user_id uuid,   -- NULL is allowed so an ownerless agent can be found and flagged (FR-ID-2)
  environment text NOT NULL DEFAULT 'dev',
  criticality text NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
  model_id uuid,
  identity_ref text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'suspended', 'retired')),
  approved_by uuid,
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, identity_ref),
  FOREIGN KEY (tenant_id, owner_user_id) REFERENCES users (tenant_id, id),
  FOREIGN KEY (tenant_id, model_id) REFERENCES models (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_by) REFERENCES users (tenant_id, id),
  FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id),
  CONSTRAINT agents_approver_not_owner CHECK (approved_by IS NULL OR approved_by IS DISTINCT FROM owner_user_id)
);

CREATE TABLE mcp_servers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  namespace text NOT NULL CHECK (namespace ~ '^[a-z0-9][a-z0-9_-]*$' AND namespace NOT LIKE '%\_\_%'),
  url text NOT NULL CHECK (url ~ '^https?://'),   -- validated by the SSRF guard before insert (WP-1.3)
  -- Phase 1: Streamable HTTP only and no upstream credential (plan Section 4.4). A later migration widens these.
  transport text NOT NULL DEFAULT 'streamable_http' CHECK (transport = 'streamable_http'),
  credential_mode text NOT NULL DEFAULT 'none' CHECK (credential_mode = 'none'),
  owner_user_id uuid,
  environment text NOT NULL DEFAULT 'dev',
  criticality text NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
  trust_tier text NOT NULL DEFAULT 'untrusted',
  jwks_ref text,
  classification_level_id uuid,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'quarantined', 'retired')),
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, namespace),
  FOREIGN KEY (tenant_id, owner_user_id) REFERENCES users (tenant_id, id),
  FOREIGN KEY (tenant_id, classification_level_id) REFERENCES classification_levels (tenant_id, id),
  FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
);

CREATE TABLE server_egress_allow (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  server_id uuid NOT NULL,
  destination text NOT NULL,
  port int NOT NULL CHECK (port BETWEEN 1 AND 65535),
  reason text NOT NULL,
  approved_by uuid NOT NULL,        -- SSRF exception entries carry owner, reason and expiry (FR-SSRF-5)
  expires_at timestamptz NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, server_id, destination, port),
  FOREIGN KEY (tenant_id, server_id) REFERENCES mcp_servers (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_by) REFERENCES users (tenant_id, id)
);

CREATE TABLE tools (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  server_id uuid NOT NULL,
  name text NOT NULL CHECK (name <> ''),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'quarantined', 'rejected')),
  action_class text NOT NULL CHECK (action_class IN ('read', 'write', 'execute', 'delete')),  -- set at approval, never from annotations
  classification_level_id uuid,
  current_version_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (server_id, name),
  FOREIGN KEY (tenant_id, server_id) REFERENCES mcp_servers (tenant_id, id),
  FOREIGN KEY (tenant_id, classification_level_id) REFERENCES classification_levels (tenant_id, id),
  CONSTRAINT tools_approved_has_version CHECK (status <> 'approved' OR current_version_id IS NOT NULL)
);

CREATE TABLE rule_sets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  version text NOT NULL,
  content_hash bytea NOT NULL CHECK (octet_length(content_hash) = 32),
  published_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, version)
);

CREATE TABLE scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  server_id uuid NOT NULL,
  rule_set_id uuid NOT NULL,
  risk_score numeric(5, 2) CHECK (risk_score BETWEEN 0 AND 100),
  status text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed', 'timeout')),
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, server_id) REFERENCES mcp_servers (tenant_id, id),
  FOREIGN KEY (tenant_id, rule_set_id) REFERENCES rule_sets (tenant_id, id)
);

CREATE TABLE tool_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  tool_id uuid NOT NULL,
  version_no int NOT NULL CHECK (version_no >= 1),
  canonical_json jsonb NOT NULL,
  sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
  scan_id uuid,
  approved_by uuid NOT NULL,
  approved_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tool_id, version_no),
  UNIQUE (tool_id, sha256),
  FOREIGN KEY (tenant_id, tool_id) REFERENCES tools (tenant_id, id),
  FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_by) REFERENCES users (tenant_id, id)
);

ALTER TABLE tools ADD CONSTRAINT tools_current_version_fk
  FOREIGN KEY (tenant_id, current_version_id) REFERENCES tool_versions (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;

CREATE TABLE data_sources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  name text NOT NULL,
  type text NOT NULL,
  classification_level_id uuid,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  FOREIGN KEY (tenant_id, classification_level_id) REFERENCES classification_levels (tenant_id, id)
);

CREATE TABLE enterprise_systems (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  name text NOT NULL,
  type text NOT NULL,
  classification_level_id uuid,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  FOREIGN KEY (tenant_id, classification_level_id) REFERENCES classification_levels (tenant_id, id)
);

CREATE TABLE graph_edges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  from_type text NOT NULL CHECK (from_type IN ('agent', 'model', 'server', 'tool', 'data_source', 'system')),
  from_id uuid NOT NULL,
  to_type text NOT NULL CHECK (to_type IN ('agent', 'model', 'server', 'tool', 'data_source', 'system')),
  to_id uuid NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, from_type, from_id, to_type, to_id)
);

CREATE TABLE agent_server_allow (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  agent_id uuid NOT NULL,
  server_id uuid NOT NULL,
  approved_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, agent_id, server_id),
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
  FOREIGN KEY (tenant_id, server_id) REFERENCES mcp_servers (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_by) REFERENCES users (tenant_id, id)
);

-- ------------------------------------------------------------------ 3.3 authorization
CREATE TABLE permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  agent_id uuid NOT NULL,
  tool_id uuid NOT NULL,
  action_classes text[] NOT NULL CHECK (cardinality(action_classes) > 0
                                        AND action_classes <@ ARRAY['read','write','execute','delete']),
  resource_pattern text NOT NULL DEFAULT '*',
  grant_type text NOT NULL CHECK (grant_type IN ('static', 'jit')),
  expires_at timestamptz,
  requested_by uuid NOT NULL,
  approved_by uuid NOT NULL,
  reason text,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
  FOREIGN KEY (tenant_id, tool_id) REFERENCES tools (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES users (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_by) REFERENCES users (tenant_id, id),
  CONSTRAINT permissions_jit_expiry CHECK (grant_type <> 'jit' OR expires_at IS NOT NULL),
  CONSTRAINT permissions_sod CHECK (requested_by <> approved_by)
);

CREATE TABLE approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  subject_type text NOT NULL CHECK (subject_type IN ('tool_version', 'agent', 'grant', 'call')),
  subject_id uuid NOT NULL,
  arguments_hash bytea CHECK (arguments_hash IS NULL OR octet_length(arguments_hash) = 32),
  requested_by uuid NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  decided_by uuid,
  decided_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES users (tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES users (tenant_id, id),
  CONSTRAINT approvals_sod CHECK (decided_by IS NULL OR decided_by <> requested_by),
  CONSTRAINT approvals_decision_complete CHECK ((status IN ('approved', 'rejected')) = (decided_by IS NOT NULL AND decided_at IS NOT NULL)
                                                OR status IN ('pending', 'expired')),
  CONSTRAINT approvals_call_binds_args CHECK (subject_type <> 'call' OR arguments_hash IS NOT NULL)
);

-- ------------------------------------------------------------------ 3.4 security data
CREATE TABLE scan_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  server_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('import', 'rescan')),
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'claimed', 'done', 'failed')),
  claimed_by text,
  lease_expires_at timestamptz,
  attempts int NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts int NOT NULL DEFAULT 3 CHECK (max_attempts >= 1),
  result_scan_id uuid,
  failure_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, server_id) REFERENCES mcp_servers (tenant_id, id),
  FOREIGN KEY (tenant_id, result_scan_id) REFERENCES scans (tenant_id, id),
  CONSTRAINT scan_jobs_claim_has_lease CHECK (status <> 'claimed' OR (claimed_by IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CONSTRAINT scan_jobs_failed_has_reason CHECK (status <> 'failed' OR failure_reason IS NOT NULL)
);

CREATE TABLE findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  scan_id uuid NOT NULL,
  tool_version_id uuid,
  rule_id text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  location text,
  evidence_excerpt text CHECK (evidence_excerpt IS NULL OR length(evidence_excerpt) <= 512),
  confidence numeric(4, 3) CHECK (confidence BETWEEN 0 AND 1),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'accepted', 'fixed')),
  waiver_expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, scan_id) REFERENCES scans (tenant_id, id),
  FOREIGN KEY (tenant_id, tool_version_id) REFERENCES tool_versions (tenant_id, id),
  CONSTRAINT findings_accepted_expires CHECK (status <> 'accepted' OR waiver_expires_at IS NOT NULL)
);

CREATE TABLE overrides (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  approval_id uuid NOT NULL,
  finding_id uuid NOT NULL,
  justification text NOT NULL CHECK (length(justification) >= 10),
  expires_at timestamptz NOT NULL,
  effective_at timestamptz,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, approval_id) REFERENCES approvals (tenant_id, id),
  FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id)
);

CREATE TABLE override_approvers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  override_id uuid NOT NULL,
  approver_user_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (override_id, approver_user_id),   -- two distinct approvers (SoD-2)
  FOREIGN KEY (tenant_id, override_id) REFERENCES overrides (tenant_id, id),
  FOREIGN KEY (tenant_id, approver_user_id) REFERENCES users (tenant_id, id)
);

-- An override approver may not be the requester of the approval the override belongs to.
CREATE FUNCTION override_approver_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM overrides o JOIN approvals a ON a.tenant_id = o.tenant_id AND a.id = o.approval_id
             WHERE o.tenant_id = NEW.tenant_id AND o.id = NEW.override_id AND a.requested_by = NEW.approver_user_id) THEN
    RAISE EXCEPTION 'override approver must differ from the requester (SoD-2)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER override_approvers_sod BEFORE INSERT ON override_approvers
  FOR EACH ROW EXECUTE FUNCTION override_approver_check();

-- An override takes effect only with two distinct approvers (SoD-2).
CREATE FUNCTION override_effect_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.effective_at IS NOT NULL AND
     (SELECT count(DISTINCT approver_user_id) FROM override_approvers
      WHERE tenant_id = NEW.tenant_id AND override_id = NEW.id) < 2 THEN
    RAISE EXCEPTION 'an override needs two distinct approvers before it takes effect (SoD-2)'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER overrides_two_approvers BEFORE INSERT OR UPDATE OF effective_at ON overrides
  FOR EACH ROW EXECUTE FUNCTION override_effect_check();

CREATE TABLE incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  severity text NOT NULL CHECK (severity IN ('sev1', 'sev2', 'sev3', 'sev4')),
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'contained', 'resolved', 'closed')),
  opened_by uuid NOT NULL,
  commander uuid,
  summary text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, opened_by) REFERENCES users (tenant_id, id),
  FOREIGN KEY (tenant_id, commander) REFERENCES users (tenant_id, id)
);

CREATE TABLE incident_assets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  incident_id uuid NOT NULL,
  asset_type text NOT NULL CHECK (asset_type IN ('agent', 'server', 'tool')),
  asset_id uuid NOT NULL,
  UNIQUE (tenant_id, id),
  UNIQUE (incident_id, asset_type, asset_id),
  FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id)
);

CREATE TABLE evidence_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  incident_id uuid,
  object_ref text NOT NULL,
  sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
  collected_by uuid NOT NULL,
  collected_at timestamptz NOT NULL DEFAULT now(),
  legal_hold boolean NOT NULL DEFAULT false,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id),
  FOREIGN KEY (tenant_id, collected_by) REFERENCES users (tenant_id, id)
);

-- ------------------------------------------------------------------ 3.5 audit
CREATE TABLE audit_events (
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  seq bigint NOT NULL CHECK (seq >= 1),
  event_id text NOT NULL,
  -- Supplied by the chain writer in UTC with microseconds so the hash input can be rebuilt exactly.
  occurred_at timestamptz NOT NULL,
  event_type text NOT NULL CHECK (event_type ~ '^[a-z_]+\.[a-z_.]+$'),
  actor text NOT NULL,
  subject_type text,
  subject_id text,
  decision text,
  policy_hash text CHECK (policy_hash IS NULL OR policy_hash ~ '^[0-9a-f]{64}$'),
  input_digest text CHECK (input_digest IS NULL OR input_digest ~ '^[0-9a-f]{64}$'),
  payload_digest text CHECK (payload_digest IS NULL OR payload_digest ~ '^[0-9a-f]{64}$'),
  redacted_excerpt text CHECK (redacted_excerpt IS NULL OR length(redacted_excerpt) <= 256),
  prev_hash bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
  hash bytea NOT NULL CHECK (octet_length(hash) = 32),
  PRIMARY KEY (tenant_id, seq),
  UNIQUE (tenant_id, event_id)
);

-- The head of each tenant's chain. Locking this row serialises writers per tenant; the trigger below
-- refuses an event whose sequence or previous hash does not continue the chain, so a gap, a fork or a
-- reordered insert fails in the database, not only in the verifier.
CREATE TABLE audit_chain_heads (
  tenant_id uuid PRIMARY KEY REFERENCES tenants (id),
  seq bigint NOT NULL,
  hash bytea NOT NULL CHECK (octet_length(hash) = 32)
);

CREATE FUNCTION audit_chain_link() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE head audit_chain_heads%ROWTYPE;
BEGIN
  INSERT INTO audit_chain_heads (tenant_id, seq, hash)
    VALUES (NEW.tenant_id, 0, decode(repeat('00', 32), 'hex')) ON CONFLICT DO NOTHING;
  SELECT * INTO head FROM audit_chain_heads WHERE tenant_id = NEW.tenant_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit chain head is not visible for this tenant' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.seq <> head.seq + 1 THEN
    RAISE EXCEPTION 'audit sequence % does not follow %', NEW.seq, head.seq USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.prev_hash <> head.hash THEN
    RAISE EXCEPTION 'audit prev_hash does not match the chain head' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  UPDATE audit_chain_heads SET seq = NEW.seq, hash = NEW.hash WHERE tenant_id = NEW.tenant_id;
  RETURN NEW;
END $$;
CREATE TRIGGER audit_events_chain BEFORE INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_chain_link();

CREATE TABLE anchor_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  seq_from bigint NOT NULL,
  seq_to bigint NOT NULL,
  head_hash bytea NOT NULL CHECK (octet_length(head_hash) = 32),
  anchored_at timestamptz NOT NULL DEFAULT now(),
  anchor_ref text NOT NULL,
  CHECK (seq_to >= seq_from),
  UNIQUE (tenant_id, seq_to)
);

CREATE TABLE outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  event jsonb NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'processed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz
);

-- ------------------------------------------------------------------ 3.6 governance
CREATE TABLE controls (
  control_id text PRIMARY KEY CHECK (control_id ~ '^CTL-[0-9]{2}$'),
  title text NOT NULL,
  phase int NOT NULL CHECK (phase BETWEEN 1 AND 5)
);

CREATE TABLE control_mappings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  control_id text NOT NULL REFERENCES controls (control_id),
  framework text NOT NULL,
  item text NOT NULL,
  status_type text NOT NULL CHECK (status_type IN ('mandatory', 'guidance', 'voluntary')),
  reviewed_by text,
  reviewed_at timestamptz,
  UNIQUE (control_id, framework, item)
);

CREATE TABLE retention_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  data_class text NOT NULL CHECK (data_class IN ('audit', 'evidence', 'scans', 'sessions', 'notifications')),
  hot_days int NOT NULL CHECK (hot_days > 0),
  cold_days int NOT NULL CHECK (cold_days >= 0),
  legal_hold_allowed boolean NOT NULL DEFAULT true,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, data_class)
);

CREATE TABLE config_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  scope text NOT NULL,
  content_hash bytea NOT NULL CHECK (octet_length(content_hash) = 32),
  applied_by uuid NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, applied_by) REFERENCES users (tenant_id, id)
);

-- ------------------------------------------------------------------ immutability (owner included)
CREATE TRIGGER tool_versions_immutable BEFORE UPDATE OR DELETE ON tool_versions
  FOR EACH ROW EXECUTE FUNCTION forbid_change();
CREATE TRIGGER tool_versions_no_truncate BEFORE TRUNCATE ON tool_versions
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_change();
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION forbid_change();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION forbid_change();
CREATE TRIGGER anchor_records_immutable BEFORE UPDATE OR DELETE ON anchor_records
  FOR EACH ROW EXECUTE FUNCTION forbid_change();

-- ------------------------------------------------------------------ indexes (data-model Section 7; to be load-tested, TC-Z18)
CREATE INDEX tools_by_server_name ON tools (tenant_id, server_id, name);
CREATE INDEX tools_by_status ON tools (tenant_id, status);
CREATE INDEX tool_versions_by_tool_hash ON tool_versions (tool_id, sha256);
CREATE INDEX findings_by_version ON findings (tenant_id, tool_version_id, severity, status);
CREATE INDEX approvals_pending ON approvals (tenant_id, status, subject_type) WHERE status = 'pending';
CREATE INDEX permissions_by_agent ON permissions (tenant_id, agent_id, tool_id);
CREATE INDEX scan_jobs_claimable ON scan_jobs (status, lease_expires_at) WHERE status IN ('queued', 'claimed');
CREATE INDEX audit_events_by_subject ON audit_events (tenant_id, subject_type, subject_id, occurred_at);
CREATE INDEX outbox_pending ON outbox (id) WHERE state = 'pending';
CREATE INDEX role_bindings_by_user ON role_bindings (tenant_id, user_id);

-- ------------------------------------------------------------------ row-level security on every table with a tenant_id
DO $$
DECLARE t text;
BEGIN
  FOR t IN SELECT c.relname FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid
           WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r'
             AND a.attname = 'tenant_id' AND NOT a.attisdropped
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())', t);
  END LOOP;
END $$;

-- tenants has no tenant_id: a session sees only its own row and cannot write it.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY own_tenant ON tenants FOR SELECT USING (id = current_tenant());

-- ------------------------------------------------------------------ privileges
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO app_role, audit_writer, readonly_reporting;
GRANT EXECUTE ON FUNCTION current_tenant() TO app_role, audit_writer, readonly_reporting;

-- Application role: DML on application tables; read-only on the audit chain; insert on the outbox.
GRANT SELECT ON tenants, controls, control_mappings TO app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  users, role_bindings, classification_levels, models, agents, mcp_servers, server_egress_allow, tools,
  rule_sets, scans, data_sources, enterprise_systems, graph_edges, agent_server_allow, permissions,
  approvals, scan_jobs, findings, overrides, override_approvers, incidents, incident_assets,
  evidence_items, retention_policies, config_versions TO app_role;
GRANT SELECT, INSERT ON tool_versions TO app_role;          -- never update or delete
GRANT SELECT ON audit_events, anchor_records TO app_role;
GRANT INSERT, SELECT ON outbox TO app_role;

-- Audit writer: the only role that writes the chain. It reads the outbox and marks rows processed.
GRANT SELECT ON tenants TO audit_writer;
GRANT SELECT, INSERT ON audit_events, anchor_records TO audit_writer;
GRANT SELECT ON outbox TO audit_writer;
GRANT UPDATE (state, processed_at) ON outbox TO audit_writer;

-- Reporting: read-only, still bound by row-level security.
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_reporting;
REVOKE SELECT ON outbox, audit_chain_heads FROM readonly_reporting;

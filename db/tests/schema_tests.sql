-- WP-1.5 schema tests. Run after the migrations, as a superuser, with
--   psql -v ON_ERROR_STOP=1 -f schema_tests.sql
-- Every check prints PASS, or raises an exception and stops the script.
SET client_min_messages = notice;

CREATE SCHEMA t;
GRANT USAGE ON SCHEMA t TO app_role, audit_writer, readonly_reporting;

CREATE FUNCTION t.expect_error(sql text, label text, pattern text DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
DECLARE msg text; failed boolean := false;
BEGIN
  BEGIN EXECUTE sql; EXCEPTION WHEN OTHERS THEN failed := true; msg := SQLERRM; END;
  IF NOT failed THEN RAISE EXCEPTION 'FAIL %: statement succeeded', label; END IF;
  IF pattern IS NOT NULL AND msg NOT LIKE '%' || pattern || '%' THEN RAISE EXCEPTION 'FAIL %: wrong error: %', label, msg; END IF;
  RAISE NOTICE 'PASS %', label;
END $$;
CREATE FUNCTION t.expect_rows(sql text, n bigint, label text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE c bigint;
BEGIN EXECUTE sql; GET DIAGNOSTICS c = ROW_COUNT;
  IF c <> n THEN RAISE EXCEPTION 'FAIL %: % rows affected, expected %', label, c, n; END IF;
  RAISE NOTICE 'PASS %', label; END $$;
CREATE FUNCTION t.expect_eq(actual bigint, expected bigint, label text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'FAIL %: got %, expected %', label, actual, expected; END IF;
  RAISE NOTICE 'PASS %', label; END $$;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA t TO app_role, audit_writer, readonly_reporting;

-- ================================================================ structure (catalogue checks)
-- every table with a tenant_id has forced RLS and a policy with USING and WITH CHECK on current_tenant()
SELECT t.expect_eq((SELECT count(*) FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' AND a.attname = 'tenant_id' AND NOT a.attisdropped
     AND NOT (c.relrowsecurity AND c.relforcerowsecurity)), 0, 'every table with tenant_id has row-level security enabled and forced');
SELECT t.expect_eq((SELECT count(*) FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' AND a.attname = 'tenant_id' AND NOT a.attisdropped
     AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation'
        AND pg_get_expr(p.polqual, p.polrelid) LIKE '%current_tenant()%'
        AND pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%current_tenant()%')), 0, 'every tenant table has a tenant_isolation policy with USING and WITH CHECK');
SELECT t.expect_eq((SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' AND NOT relrowsecurity
   AND relname NOT IN ('controls', 'control_mappings')), 0, 'only the two global catalogue tables lack row-level security');
SELECT t.expect_eq((SELECT count(*) FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r'
   AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
   AND c.relname NOT IN ('audit_events', 'audit_chain_heads', 'outbox', 'anchor_records')
   AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = c.oid AND k.contype IN ('u', 'p')
        AND (SELECT array_agg(attname::text ORDER BY attname) FROM pg_attribute WHERE attrelid = c.oid AND attnum = ANY (k.conkey)) = ARRAY['id', 'tenant_id'])),
   0, 'every tenant table offers unique (tenant_id, id) for composite foreign keys');
SELECT t.expect_eq((SELECT count(*) FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
   WHERE k.contype = 'f' AND c.relnamespace = 'public'::regnamespace AND c.relname NOT IN ('control_mappings')
     AND k.confrelid <> 'tenants'::regclass AND cardinality(k.conkey) = 1), 0, 'no single-column foreign key between tenant tables (all are composite with tenant_id)');
SELECT t.expect_eq((SELECT count(*) FROM pg_roles WHERE rolname IN ('app_role', 'audit_writer', 'readonly_reporting')
   AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolcanlogin)), 0, 'application roles: no superuser, BYPASSRLS, CREATEDB, CREATEROLE or login');

-- ================================================================ seed two tenants (as the application role)
INSERT INTO tenants (id, name) VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'tenant-a'), ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'tenant-b');
\set a '''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'''
\set b '''bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'''

SET ROLE app_role;
-- tenant A: users alice (requester), amir (approver), anna (second approver)
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
INSERT INTO users (id, tenant_id, external_subject) VALUES
  ('a0000000-0000-0000-0000-000000000001', :a, 'alice'), ('a0000000-0000-0000-0000-000000000002', :a, 'amir'), ('a0000000-0000-0000-0000-000000000003', :a, 'anna');
INSERT INTO role_bindings (tenant_id, user_id, role) VALUES (:a, 'a0000000-0000-0000-0000-000000000002', 'approver');
INSERT INTO classification_levels (id, tenant_id, name, rank) VALUES ('a9000000-0000-0000-0000-000000000001', :a, 'Confidential', 2);
INSERT INTO agents (id, tenant_id, name, owner_user_id) VALUES ('a1000000-0000-0000-0000-000000000001', :a, 'agent-a', 'a0000000-0000-0000-0000-000000000001');
INSERT INTO mcp_servers (id, tenant_id, namespace, url, classification_level_id) VALUES ('a2000000-0000-0000-0000-000000000001', :a, 'files', 'https://files.example.test/mcp', 'a9000000-0000-0000-0000-000000000001');
INSERT INTO tools (id, tenant_id, server_id, name, action_class) VALUES
  ('a3000000-0000-0000-0000-000000000001', :a, 'a2000000-0000-0000-0000-000000000001', 'read_doc', 'read'),
  ('a3000000-0000-0000-0000-000000000002', :a, 'a2000000-0000-0000-0000-000000000001', 'purge', 'delete');
INSERT INTO rule_sets (id, tenant_id, version, content_hash) VALUES ('a5000000-0000-0000-0000-000000000001', :a, '1', decode(repeat('01', 32), 'hex'));
INSERT INTO scans (id, tenant_id, server_id, rule_set_id) VALUES ('a6000000-0000-0000-0000-000000000001', :a, 'a2000000-0000-0000-0000-000000000001', 'a5000000-0000-0000-0000-000000000001');
INSERT INTO tool_versions (id, tenant_id, tool_id, version_no, canonical_json, sha256, scan_id, approved_by) VALUES
  ('a4000000-0000-0000-0000-000000000001', :a, 'a3000000-0000-0000-0000-000000000001', 1, '{"name":"read_doc"}', decode(repeat('ab', 32), 'hex'), 'a6000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002');
UPDATE tools SET status = 'approved', current_version_id = 'a4000000-0000-0000-0000-000000000001' WHERE id = 'a3000000-0000-0000-0000-000000000001';
INSERT INTO findings (id, tenant_id, scan_id, tool_version_id, rule_id, severity) VALUES ('a7000000-0000-0000-0000-000000000001', :a, 'a6000000-0000-0000-0000-000000000001', 'a4000000-0000-0000-0000-000000000001', 'R-OVERRIDE', 'critical');
INSERT INTO approvals (id, tenant_id, subject_type, subject_id, requested_by, decided_by, decided_at, status) VALUES
  ('a8000000-0000-0000-0000-000000000001', :a, 'tool_version', 'a4000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002', now(), 'approved');
INSERT INTO permissions (tenant_id, agent_id, tool_id, action_classes, grant_type, requested_by, approved_by) VALUES
  (:a, 'a1000000-0000-0000-0000-000000000001', 'a3000000-0000-0000-0000-000000000001', ARRAY['read'], 'static', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002');
INSERT INTO scan_jobs (tenant_id, server_id, kind) VALUES (:a, 'a2000000-0000-0000-0000-000000000001', 'import');
INSERT INTO outbox (tenant_id, event) VALUES (:a, '{"event_type":"tool.approved"}');
COMMIT;

BEGIN;
SELECT set_config('app.tenant_id', :b, true);
INSERT INTO users (id, tenant_id, external_subject) VALUES
  ('b0000000-0000-0000-0000-000000000001', :b, 'bella'), ('b0000000-0000-0000-0000-000000000002', :b, 'bao');
INSERT INTO agents (id, tenant_id, name, owner_user_id) VALUES ('b1000000-0000-0000-0000-000000000001', :b, 'agent-a', 'b0000000-0000-0000-0000-000000000001');
INSERT INTO mcp_servers (id, tenant_id, namespace, url) VALUES ('b2000000-0000-0000-0000-000000000001', :b, 'files', 'https://files.other.test/mcp');
INSERT INTO tools (id, tenant_id, server_id, name, action_class) VALUES ('b3000000-0000-0000-0000-000000000001', :b, 'b2000000-0000-0000-0000-000000000001', 'read_doc', 'read');
INSERT INTO scan_jobs (tenant_id, server_id, kind) VALUES (:b, 'b2000000-0000-0000-0000-000000000001', 'import');
INSERT INTO outbox (tenant_id, event) VALUES (:b, '{"event_type":"tool.approved"}');
COMMIT;

-- ================================================================ tenant isolation on every table, both directions
DO $$
DECLARE pair uuid[]; own uuid; t text; n bigint; c bigint; total bigint := 0;
BEGIN
  FOREACH pair SLICE 1 IN ARRAY ARRAY[['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'],['bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa']]::uuid[][]
  LOOP
    own := pair[1];
    PERFORM set_config('app.tenant_id', own::text, true);
    FOR t IN SELECT c2.relname FROM pg_class c2 JOIN pg_attribute a ON a.attrelid = c2.oid
             WHERE c2.relnamespace = 'public'::regnamespace AND c2.relkind = 'r' AND a.attname = 'tenant_id' AND NOT a.attisdropped
               AND has_table_privilege('app_role', c2.oid, 'SELECT')
    LOOP
      EXECUTE format('SELECT count(*) FROM %I WHERE tenant_id <> %L', t, own) INTO c;
      IF c <> 0 THEN RAISE EXCEPTION 'FAIL % leaks % foreign rows to %', t, c, own; END IF;
      EXECUTE format('SELECT count(*) FROM %I', t) INTO n; total := total + n;
    END LOOP;
    RAISE NOTICE 'PASS no foreign rows visible in any readable tenant table for tenant %', left(own::text, 8);
  END LOOP;
  IF total < 20 THEN RAISE EXCEPTION 'FAIL seed too small to be meaningful: %', total; END IF;
END $$;

-- writes against the other tenant touch nothing (own rows control)
DO $$
DECLARE tn text;
BEGIN
  PERFORM set_config('app.tenant_id', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', true);
  PERFORM t.expect_rows('UPDATE agents SET name = name WHERE tenant_id = ''bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb''', 0, 'update of the other tenant''s agents touches 0 rows');
  PERFORM t.expect_rows('DELETE FROM mcp_servers WHERE tenant_id = ''bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb''', 0, 'delete of the other tenant''s servers touches 0 rows');
  PERFORM t.expect_rows('UPDATE scan_jobs SET attempts = attempts WHERE tenant_id = ''bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb''', 0, 'update of the other tenant''s scan jobs touches 0 rows');
  PERFORM t.expect_rows('UPDATE agents SET name = name', 1, 'update of own agents works (control)');
END $$;

BEGIN;
SELECT set_config('app.tenant_id', :a, true);
SELECT t.expect_error(format('INSERT INTO users (tenant_id, external_subject) VALUES (%L, ''mallory'')', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'), 'insert for another tenant refused', 'row-level security');
SELECT t.expect_error(format('INSERT INTO outbox (tenant_id, event) VALUES (%L, ''{}'')', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'), 'outbox insert for another tenant refused', 'row-level security');
SELECT t.expect_error('INSERT INTO tenants (name) VALUES (''rogue'')', 'application role cannot create tenants', 'permission denied');
SELECT t.expect_eq((SELECT count(*) FROM tenants), 1, 'application role sees only its own tenant row');
COMMIT;

-- composite foreign keys: a reference across tenants is refused
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
SELECT t.expect_error(format('INSERT INTO tools (tenant_id, server_id, name, action_class) VALUES (%L, %L, ''sneaky'', ''read'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'b2000000-0000-0000-0000-000000000001'), 'tool cannot reference another tenant''s server', 'foreign key');
SELECT t.expect_error(format('INSERT INTO agents (tenant_id, name, owner_user_id) VALUES (%L, ''sneaky'', %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'b0000000-0000-0000-0000-000000000001'), 'agent cannot be owned by another tenant''s user', 'foreign key');
SELECT t.expect_error(format('INSERT INTO permissions (tenant_id, agent_id, tool_id, action_classes, grant_type, requested_by, approved_by) VALUES (%L, %L, %L, ARRAY[''read''], ''static'', %L, %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'b1000000-0000-0000-0000-000000000001', 'a3000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002'), 'grant cannot reference another tenant''s agent', 'foreign key');
COMMIT;

-- ================================================================ immutability
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
SELECT t.expect_error('UPDATE tool_versions SET canonical_json = ''{}''', 'app role cannot update tool_versions', 'permission denied');
SELECT t.expect_error('DELETE FROM tool_versions', 'app role cannot delete tool_versions', 'permission denied');
SELECT t.expect_error('TRUNCATE tool_versions', 'app role cannot truncate tool_versions', 'permission denied');
SELECT t.expect_error('UPDATE audit_events SET actor = ''x''', 'app role cannot update audit_events', 'permission denied');
SELECT t.expect_error('DELETE FROM audit_events', 'app role cannot delete audit_events', 'permission denied');
SELECT t.expect_error('INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, prev_hash, hash) VALUES (''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'', 1, ''x'', now(), ''a.b'', ''x'', ''\x00'', ''\x00'')', 'app role cannot write the audit chain directly', 'permission denied');
SELECT t.expect_error('INSERT INTO audit_chain_heads (tenant_id, seq, hash) VALUES (''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'', 5, ''\x00'')', 'app role cannot touch chain heads', 'permission denied');
SELECT t.expect_error('INSERT INTO tool_versions (tenant_id, tool_id, version_no, canonical_json, sha256, approved_by) VALUES (''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'', ''a3000000-0000-0000-0000-000000000001'', 2, ''{}'', decode(repeat(''ab'', 32), ''hex''), ''a0000000-0000-0000-0000-000000000002'')', 'same definition hash cannot be stored twice for a tool', 'duplicate key');
SELECT t.expect_error('INSERT INTO tool_versions (tenant_id, tool_id, version_no, canonical_json, sha256, approved_by) VALUES (''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'', ''a3000000-0000-0000-0000-000000000001'', 1, ''{}'', decode(repeat(''cc'', 32), ''hex''), ''a0000000-0000-0000-0000-000000000002'')', 'version number cannot be reused', 'duplicate key');
COMMIT;
RESET ROLE;
SELECT t.expect_error('UPDATE tool_versions SET canonical_json = ''{}''', 'owner cannot update tool_versions (trigger)', 'immutable');
SELECT t.expect_error('DELETE FROM tool_versions', 'owner cannot delete tool_versions (trigger)', 'immutable');
SELECT t.expect_error('TRUNCATE tool_versions CASCADE', 'owner cannot truncate tool_versions even with CASCADE (trigger)', 'immutable');
SELECT t.expect_error('TRUNCATE audit_events', 'owner cannot truncate audit_events (trigger)', 'immutable');
INSERT INTO anchor_records (tenant_id, seq_from, seq_to, head_hash, anchor_ref) VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 1, 1, decode(repeat('11', 32), 'hex'), 'test-anchor');
SELECT t.expect_error('DELETE FROM anchor_records', 'owner cannot delete anchor records (trigger)', 'immutable');
SELECT t.expect_error('UPDATE anchor_records SET anchor_ref = ''x''', 'owner cannot update anchor records (trigger)', 'immutable');

-- ================================================================ separation of duties and constraints
SET ROLE app_role;
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
SELECT t.expect_error(format('INSERT INTO approvals (tenant_id, subject_type, subject_id, requested_by, decided_by, decided_at, status) VALUES (%L, ''agent'', gen_random_uuid(), %L, %L, now(), ''approved'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001'), 'approver equal to requester refused', 'approvals_sod');
SELECT t.expect_error(format('INSERT INTO approvals (tenant_id, subject_type, subject_id, requested_by, status) VALUES (%L, ''agent'', gen_random_uuid(), %L, ''approved'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a0000000-0000-0000-0000-000000000001'), 'an approved decision needs a decider and time', 'approvals_decision_complete');
SELECT t.expect_error(format('INSERT INTO approvals (tenant_id, subject_type, subject_id, requested_by) VALUES (%L, ''call'', gen_random_uuid(), %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a0000000-0000-0000-0000-000000000001'), 'a call approval must bind the argument hash', 'approvals_call_binds_args');
SELECT t.expect_error(format('INSERT INTO permissions (tenant_id, agent_id, tool_id, action_classes, grant_type, requested_by, approved_by) VALUES (%L, %L, %L, ARRAY[''read''], ''jit'', %L, %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a1000000-0000-0000-0000-000000000001', 'a3000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002'), 'JIT grant without expiry refused', 'permissions_jit_expiry');
SELECT t.expect_error(format('INSERT INTO permissions (tenant_id, agent_id, tool_id, action_classes, grant_type, requested_by, approved_by) VALUES (%L, %L, %L, ARRAY[''read''], ''static'', %L, %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a1000000-0000-0000-0000-000000000001', 'a3000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001'), 'grant approved by its requester refused', 'permissions_sod');
SELECT t.expect_error(format('INSERT INTO permissions (tenant_id, agent_id, tool_id, action_classes, grant_type, requested_by, approved_by) VALUES (%L, %L, %L, ARRAY[''admin''], ''static'', %L, %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a1000000-0000-0000-0000-000000000001', 'a3000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002'), 'unknown action class refused', 'check constraint');
SELECT t.expect_error(format('UPDATE agents SET approved_by = owner_user_id WHERE tenant_id = %L', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 'agent cannot be approved by its owner', 'agents_approver_not_owner');
SELECT t.expect_error(format('INSERT INTO mcp_servers (tenant_id, namespace, url) VALUES (%L, ''files'', ''https://dup.test'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 'duplicate namespace in a tenant refused', 'duplicate key');
SELECT t.expect_error(format('INSERT INTO mcp_servers (tenant_id, namespace, url) VALUES (%L, ''a__b'', ''https://x.test'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 'namespace containing the separator refused', 'check constraint');
SELECT t.expect_error(format('INSERT INTO mcp_servers (tenant_id, namespace, url, transport) VALUES (%L, ''stdio1'', ''https://x.test'', ''stdio'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 'Phase 1 refuses a transport other than streamable_http', 'check constraint');
SELECT t.expect_error(format('INSERT INTO mcp_servers (tenant_id, namespace, url, credential_mode) VALUES (%L, ''cred1'', ''https://x.test'', ''static_secret'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 'Phase 1 refuses an upstream credential mode other than none', 'check constraint');
SELECT t.expect_error(format('INSERT INTO mcp_servers (tenant_id, namespace, url) VALUES (%L, ''file1'', ''file:///etc/passwd'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 'a non-http URL scheme is refused', 'check constraint');
SELECT t.expect_error('UPDATE tools SET status = ''approved'', current_version_id = NULL WHERE name = ''purge''', 'an approved tool must have a current version', 'tools_approved_has_version');
SELECT t.expect_error(format('INSERT INTO findings (tenant_id, scan_id, rule_id, severity, status) VALUES (%L, %L, ''R'', ''high'', ''accepted'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a6000000-0000-0000-0000-000000000001'), 'an accepted finding must carry a waiver expiry', 'findings_accepted_expires');
SELECT t.expect_error(format('INSERT INTO scan_jobs (tenant_id, server_id, kind, status) VALUES (%L, %L, ''import'', ''claimed'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a2000000-0000-0000-0000-000000000001'), 'a claimed job must carry a claimant and lease', 'scan_jobs_claim_has_lease');
COMMIT;

-- dual-approver override (SoD-2)
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
INSERT INTO approvals (id, tenant_id, subject_type, subject_id, requested_by) VALUES
  ('a8000000-0000-0000-0000-000000000002', :a, 'tool_version', 'a4000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001');
INSERT INTO overrides (id, tenant_id, approval_id, finding_id, justification, expires_at) VALUES
  ('aa000000-0000-0000-0000-000000000001', :a, 'a8000000-0000-0000-0000-000000000002', 'a7000000-0000-0000-0000-000000000001', 'accepted risk for the pilot', now() + interval '7 days');
SELECT t.expect_error('UPDATE overrides SET effective_at = now()', 'override without approvers cannot take effect', 'two distinct approvers');
SELECT t.expect_error(format('INSERT INTO override_approvers (tenant_id, override_id, approver_user_id) VALUES (%L, %L, %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'aa000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001'), 'the requester cannot approve their own override', 'SoD-2');
INSERT INTO override_approvers (tenant_id, override_id, approver_user_id) VALUES (:a, 'aa000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002');
SELECT t.expect_error('UPDATE overrides SET effective_at = now()', 'one approver is not enough for an override', 'two distinct approvers');
SELECT t.expect_error(format('INSERT INTO override_approvers (tenant_id, override_id, approver_user_id) VALUES (%L, %L, %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'aa000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002'), 'the same approver cannot count twice', 'duplicate key');
INSERT INTO override_approvers (tenant_id, override_id, approver_user_id) VALUES (:a, 'aa000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000003');
SELECT t.expect_rows('UPDATE overrides SET effective_at = now()', 1, 'two distinct approvers let the override take effect');
ROLLBACK;

-- ================================================================ audit chain: only audit_writer writes, the database enforces the link
RESET ROLE;
SET ROLE audit_writer;
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, prev_hash, hash)
  VALUES (:a, 1, 'ev-1', '2026-11-23T10:00:00.000000Z', 'tool.approved', 'amir', decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'));
COMMIT;
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
SELECT t.expect_error('INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, prev_hash, hash) VALUES (''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'', 3, ''ev-3'', now(), ''tool.approved'', ''x'', decode(repeat(''11'', 32), ''hex''), decode(repeat(''33'', 32), ''hex''))', 'a gap in the sequence is refused', 'does not follow');
SELECT t.expect_error('INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, prev_hash, hash) VALUES (''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'', 1, ''ev-1b'', now(), ''tool.approved'', ''x'', decode(repeat(''00'', 32), ''hex''), decode(repeat(''44'', 32), ''hex''))', 'a fork at an existing sequence is refused', 'does not follow');
SELECT t.expect_error('INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, prev_hash, hash) VALUES (''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'', 2, ''ev-2'', now(), ''tool.approved'', ''x'', decode(repeat(''99'', 32), ''hex''), decode(repeat(''22'', 32), ''hex''))', 'a wrong previous hash is refused', 'prev_hash');
SELECT t.expect_error('INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, prev_hash, hash) VALUES (''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'', 2, ''ev-1'', now(), ''tool.approved'', ''x'', decode(repeat(''11'', 32), ''hex''), decode(repeat(''22'', 32), ''hex''))', 'a repeated event id is refused', 'duplicate key');
SELECT t.expect_error('INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, prev_hash, hash) VALUES (''bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'', 1, ''ev-b'', now(), ''tool.approved'', ''x'', decode(repeat(''00'', 32), ''hex''), decode(repeat(''55'', 32), ''hex''))', 'the writer cannot write another tenant''s chain', 'row-level security');
SELECT t.expect_error('UPDATE audit_events SET actor = ''x''', 'audit writer cannot update events', 'permission denied');
SELECT t.expect_error('DELETE FROM audit_events', 'audit writer cannot delete events', 'permission denied');
SELECT t.expect_error('UPDATE outbox SET event = ''{}''', 'audit writer cannot edit outbox payloads', 'permission denied');
SELECT t.expect_error('INSERT INTO agents (tenant_id, name) VALUES (''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'', ''x'')', 'audit writer has no other write rights', 'permission denied');
COMMIT;
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, prev_hash, hash)
  VALUES (:a, 2, 'ev-2', '2026-11-23T10:00:01.000000Z', 'tool.approved', 'amir', decode(repeat('11', 32), 'hex'), decode(repeat('22', 32), 'hex'));
SELECT t.expect_rows('UPDATE outbox SET state = ''processed'', processed_at = now()', 1, 'audit writer marks the tenant''s outbox rows processed');
COMMIT;
BEGIN;
SELECT set_config('app.tenant_id', :b, true);
INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, prev_hash, hash)
  VALUES (:b, 1, 'ev-1', now(), 'tool.approved', 'bao', decode(repeat('00', 32), 'hex'), decode(repeat('66', 32), 'hex'));
COMMIT;
RESET ROLE;
SELECT t.expect_eq((SELECT seq FROM audit_chain_heads WHERE tenant_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 2, 'chain head of tenant A is at 2');
SELECT t.expect_eq((SELECT seq FROM audit_chain_heads WHERE tenant_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'), 1, 'chain heads are independent per tenant');
SELECT t.expect_error('UPDATE audit_events SET actor = ''x''', 'owner cannot update audit_events (trigger)', 'immutable');
SELECT t.expect_error('DELETE FROM audit_events', 'owner cannot delete audit_events (trigger)', 'immutable');
SET ROLE app_role;
BEGIN; SELECT set_config('app.tenant_id', :a, true);
SELECT t.expect_eq((SELECT count(*) FROM audit_events), 2, 'application role can read its tenant''s audit events');
SELECT t.expect_eq((SELECT count(*) FROM outbox WHERE state = 'processed'), 1, 'the processed outbox row is visible to the application');
COMMIT;

-- ================================================================ pooled connection: tenant is per transaction
BEGIN; SELECT set_config('app.tenant_id', :a, true); SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT t.expect_eq(:n, 2, 'request 1 (tenant A) sees its 2 tools');
BEGIN; SELECT set_config('app.tenant_id', :b, true); SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT t.expect_eq(:n, 1, 'request 2 (tenant B) on the same connection sees its 1 tool');
BEGIN; SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT t.expect_eq(:n, 0, 'request 3 (sets no tenant) sees nothing');
SELECT current_setting('app.tenant_id', true) AS leftover \gset
SELECT t.expect_eq((:'leftover' = '')::int, 1, 'transaction-local setting is empty after the transaction, not stale');
BEGIN; SELECT set_config('app.tenant_id', 'not-a-uuid', true);
SELECT t.expect_error('SELECT count(*) FROM tools', 'malformed tenant setting errors instead of matching', 'invalid input syntax');
ROLLBACK;
SELECT set_config('app.tenant_id', :a, false);
BEGIN; SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT t.expect_eq(:n, 2, 'DEMONSTRATION: a session-level setting leaks into the next request (forbidden)');
RESET ROLE; DISCARD ALL; SET ROLE app_role;
BEGIN; SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT t.expect_eq(:n, 0, 'DISCARD ALL on return to the pool removes the leaked setting');
SELECT t.expect_error('CREATE TABLE sneaky (i int)', 'application role cannot create tables', 'permission denied');

-- ================================================================ reporting role is read-only and still bound by RLS
RESET ROLE;
SET ROLE readonly_reporting;
BEGIN; SELECT set_config('app.tenant_id', :b, true);
SELECT t.expect_eq((SELECT count(*) FROM agents), 1, 'reporting role sees only the current tenant');
SELECT t.expect_error('DELETE FROM agents', 'reporting role cannot delete', 'permission denied');
SELECT t.expect_error('SELECT * FROM outbox', 'reporting role cannot read the outbox', 'permission denied');
COMMIT;
RESET ROLE;
\echo ALL CHECKS PASSED

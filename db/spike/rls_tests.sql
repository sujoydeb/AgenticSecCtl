-- Spike tests for checklist row P0-19. Run after 0001_core.up.sql, as a superuser, with
--   psql -v ON_ERROR_STOP=1 -f rls_tests.sql
-- Every check prints PASS, or raises an exception and stops the script.

SET client_min_messages = notice;

CREATE SCHEMA spike_test;
GRANT USAGE ON SCHEMA spike_test TO app_role;

CREATE FUNCTION spike_test.expect_error(sql text, label text, pattern text DEFAULT NULL) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE msg text; failed boolean := false;
BEGIN
  BEGIN
    EXECUTE sql;
  EXCEPTION WHEN OTHERS THEN
    failed := true; msg := SQLERRM;
  END;
  IF NOT failed THEN RAISE EXCEPTION 'FAIL %: statement succeeded', label; END IF;
  IF pattern IS NOT NULL AND msg NOT LIKE '%' || pattern || '%' THEN
    RAISE EXCEPTION 'FAIL %: wrong error: %', label, msg;
  END IF;
  RAISE NOTICE 'PASS %', label;
END $$;

CREATE FUNCTION spike_test.expect_rows(sql text, n bigint, label text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE c bigint;
BEGIN
  EXECUTE sql;
  GET DIAGNOSTICS c = ROW_COUNT;
  IF c <> n THEN RAISE EXCEPTION 'FAIL %: % rows affected, expected %', label, c, n; END IF;
  RAISE NOTICE 'PASS %', label;
END $$;

CREATE FUNCTION spike_test.expect_eq(actual bigint, expected bigint, label text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'FAIL %: got %, expected %', label, actual, expected; END IF;
  RAISE NOTICE 'PASS %', label;
END $$;

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA spike_test TO app_role;

-- ---------------------------------------------------------------- seed
INSERT INTO tenants (id, name) VALUES
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'tenant-a'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'tenant-b');

\set a '''aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'''
\set b '''bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'''

SET ROLE app_role;

BEGIN;
SELECT set_config('app.tenant_id', :a, true);
INSERT INTO users (id, tenant_id, external_subject) VALUES
  ('a0000000-0000-0000-0000-000000000001', :a, 'alice'), ('a0000000-0000-0000-0000-000000000002', :a, 'amir');
INSERT INTO agents (id, tenant_id, name, owner_user_id) VALUES ('a1000000-0000-0000-0000-000000000001', :a, 'agent-a', 'a0000000-0000-0000-0000-000000000001');
INSERT INTO mcp_servers (id, tenant_id, namespace, url) VALUES ('a2000000-0000-0000-0000-000000000001', :a, 'files', 'https://files.example.test/mcp');
INSERT INTO tools (id, tenant_id, server_id, name, action_class) VALUES
  ('a3000000-0000-0000-0000-000000000001', :a, 'a2000000-0000-0000-0000-000000000001', 'read_doc', 'read'),
  ('a3000000-0000-0000-0000-000000000002', :a, 'a2000000-0000-0000-0000-000000000001', 'purge', 'delete');
INSERT INTO tool_versions (id, tenant_id, tool_id, version_no, canonical_json, sha256, approved_by) VALUES
  ('a4000000-0000-0000-0000-000000000001', :a, 'a3000000-0000-0000-0000-000000000001', 1, '{"name":"read_doc"}', decode(repeat('ab', 32), 'hex'), 'a0000000-0000-0000-0000-000000000002');
INSERT INTO approvals (tenant_id, subject_type, subject_id, requested_by, decided_by, status) VALUES
  (:a, 'tool_version', 'a4000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002', 'approved');
INSERT INTO permissions (tenant_id, agent_id, tool_id, action_classes, grant_type, requested_by, approved_by) VALUES
  (:a, 'a1000000-0000-0000-0000-000000000001', 'a3000000-0000-0000-0000-000000000001', ARRAY['read'], 'static', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002');
INSERT INTO scan_jobs (tenant_id, server_id, kind) VALUES (:a, 'a2000000-0000-0000-0000-000000000001', 'import');
INSERT INTO audit_events (tenant_id, seq, event_id, event_type, actor, prev_hash, hash) VALUES
  (:a, 1, gen_random_uuid(), 'tool.approved', 'amir', decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'));
COMMIT;

BEGIN;
SELECT set_config('app.tenant_id', :b, true);
INSERT INTO users (id, tenant_id, external_subject) VALUES
  ('b0000000-0000-0000-0000-000000000001', :b, 'bella'), ('b0000000-0000-0000-0000-000000000002', :b, 'bao');
INSERT INTO agents (id, tenant_id, name, owner_user_id) VALUES ('b1000000-0000-0000-0000-000000000001', :b, 'agent-a', 'b0000000-0000-0000-0000-000000000001');
INSERT INTO mcp_servers (id, tenant_id, namespace, url) VALUES ('b2000000-0000-0000-0000-000000000001', :b, 'files', 'https://files.other.test/mcp');
INSERT INTO tools (id, tenant_id, server_id, name, action_class) VALUES
  ('b3000000-0000-0000-0000-000000000001', :b, 'b2000000-0000-0000-0000-000000000001', 'read_doc', 'read');
INSERT INTO tool_versions (id, tenant_id, tool_id, version_no, canonical_json, sha256, approved_by) VALUES
  ('b4000000-0000-0000-0000-000000000001', :b, 'b3000000-0000-0000-0000-000000000001', 1, '{"name":"read_doc"}', decode(repeat('cd', 32), 'hex'), 'b0000000-0000-0000-0000-000000000002');
INSERT INTO approvals (tenant_id, subject_type, subject_id, requested_by, decided_by, status) VALUES
  (:b, 'tool_version', 'b4000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'approved');
INSERT INTO permissions (tenant_id, agent_id, tool_id, action_classes, grant_type, requested_by, approved_by) VALUES
  (:b, 'b1000000-0000-0000-0000-000000000001', 'b3000000-0000-0000-0000-000000000001', ARRAY['read'], 'static', 'b0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002');
INSERT INTO scan_jobs (tenant_id, server_id, kind) VALUES (:b, 'b2000000-0000-0000-0000-000000000001', 'import');
INSERT INTO audit_events (tenant_id, seq, event_id, event_type, actor, prev_hash, hash) VALUES
  (:b, 1, gen_random_uuid(), 'tool.approved', 'bao', decode(repeat('00', 32), 'hex'), decode(repeat('22', 32), 'hex'));
COMMIT;

-- 1. Each tenant sees only its own rows in every table, and cannot update or delete the other's
DO $$
DECLARE
  pair uuid[]; own uuid; other uuid; t text; n bigint; c bigint; upd text;
  tables text[] := ARRAY['users','agents','mcp_servers','tools','tool_versions','approvals','permissions','scan_jobs','audit_events'];
  updates jsonb := '{"users":"display_name = display_name","agents":"name = name","mcp_servers":"url = url","tools":"name = name","approvals":"status = status","permissions":"resource_pattern = resource_pattern","scan_jobs":"attempts = attempts"}';
BEGIN
  FOREACH pair SLICE 1 IN ARRAY ARRAY[['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'],['bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa']]::uuid[][]
  LOOP
    own := pair[1]; other := pair[2];
    PERFORM set_config('app.tenant_id', own::text, true);
    FOREACH t IN ARRAY tables LOOP
      EXECUTE format('SELECT count(*) FROM %I', t) INTO n;
      EXECUTE format('SELECT count(*) FROM %I WHERE tenant_id <> %L', t, own) INTO c;
      IF n = 0 OR c <> 0 THEN RAISE EXCEPTION 'FAIL read isolation on % for %: own=% foreign=%', t, own, n, c; END IF;
      EXECUTE format('SELECT count(*) FROM %I WHERE tenant_id = %L', t, other) INTO c;
      IF c <> 0 THEN RAISE EXCEPTION 'FAIL % leaks rows of %', t, other; END IF;
      upd := updates ->> t;
      IF upd IS NOT NULL THEN
        PERFORM spike_test.expect_rows(format('UPDATE %I SET %s WHERE tenant_id = %L', t, upd, other), 0, format('update of other tenant blocked on %s', t));
        PERFORM spike_test.expect_rows(format('DELETE FROM %I WHERE tenant_id = %L', t, other), 0, format('delete of other tenant blocked on %s', t));
        PERFORM spike_test.expect_rows(format('UPDATE %I SET %s WHERE tenant_id = %L', t, upd, own), n, format('update of own rows works on %s (control)', t));
      END IF;
    END LOOP;
    RAISE NOTICE 'PASS read isolation, both directions, tenant %', left(own::text, 8);
  END LOOP;
END $$;

-- 2. Writing a row for another tenant is refused by the policy itself
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
SELECT spike_test.expect_error(format('INSERT INTO users (tenant_id, external_subject) VALUES (%L, ''mallory'')', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'), 'insert for another tenant refused (users)', 'row-level security');
SELECT spike_test.expect_error(format('INSERT INTO mcp_servers (tenant_id, namespace, url) VALUES (%L, ''x'', ''https://x.test'')', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'), 'insert for another tenant refused (mcp_servers)', 'row-level security');
SELECT spike_test.expect_error(format('INSERT INTO audit_events (tenant_id, seq, event_id, event_type, actor, prev_hash, hash) VALUES (%L, 99, gen_random_uuid(), ''x'', ''x'', ''\x00'', ''\x00'')', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'), 'audit insert for another tenant refused', 'row-level security');
SELECT spike_test.expect_error('INSERT INTO tenants (name) VALUES (''rogue'')', 'application role cannot create tenants', 'permission denied');
SELECT spike_test.expect_eq((SELECT count(*) FROM tenants), 1, 'application role sees only its own tenant row');
COMMIT;

-- 3. A reference across tenants is refused by the composite foreign key (plain id keys would allow it,
--    because referential-integrity checks bypass row-level security)
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
SELECT spike_test.expect_error(format('INSERT INTO tools (tenant_id, server_id, name, action_class) VALUES (%L, %L, ''sneaky'', ''read'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'b2000000-0000-0000-0000-000000000001'), 'tool cannot reference another tenant''s server', 'foreign key');
SELECT spike_test.expect_error(format('INSERT INTO agents (tenant_id, name, owner_user_id) VALUES (%L, ''sneaky'', %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'b0000000-0000-0000-0000-000000000001'), 'agent cannot be owned by another tenant''s user', 'foreign key');
COMMIT;

-- 4. Immutability: tool_versions and audit_events, for the application role and for the owner
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
SELECT spike_test.expect_error('UPDATE tool_versions SET canonical_json = ''{}''', 'app role cannot update tool_versions', 'permission denied');
SELECT spike_test.expect_error('DELETE FROM tool_versions', 'app role cannot delete tool_versions', 'permission denied');
SELECT spike_test.expect_error('TRUNCATE tool_versions', 'app role cannot truncate tool_versions', 'permission denied');
SELECT spike_test.expect_error('UPDATE audit_events SET actor = ''x''', 'app role cannot update audit_events', 'permission denied');
SELECT spike_test.expect_error('DELETE FROM audit_events', 'app role cannot delete audit_events', 'permission denied');
COMMIT;

RESET ROLE;
SELECT spike_test.expect_error('UPDATE tool_versions SET canonical_json = ''{}''', 'owner cannot update tool_versions (trigger)', 'immutable');
SELECT spike_test.expect_error('DELETE FROM tool_versions', 'owner cannot delete tool_versions (trigger)', 'immutable');
SELECT spike_test.expect_error('TRUNCATE tool_versions', 'owner cannot truncate tool_versions (trigger)', 'immutable');
SELECT spike_test.expect_error('UPDATE audit_events SET actor = ''x''', 'owner cannot update audit_events (trigger)', 'immutable');
SELECT spike_test.expect_error('DELETE FROM audit_events', 'owner cannot delete audit_events (trigger)', 'immutable');
SET ROLE app_role;

-- 5. Separation of duties and grant constraints
BEGIN;
SELECT set_config('app.tenant_id', :a, true);
SELECT spike_test.expect_error(format('INSERT INTO approvals (tenant_id, subject_type, subject_id, requested_by, decided_by, status) VALUES (%L, ''agent'', gen_random_uuid(), %L, %L, ''approved'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001'), 'approver equal to requester refused', 'approvals_sod');
SELECT spike_test.expect_error(format('INSERT INTO permissions (tenant_id, agent_id, tool_id, action_classes, grant_type, requested_by, approved_by) VALUES (%L, %L, %L, ARRAY[''read''], ''jit'', %L, %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a1000000-0000-0000-0000-000000000001', 'a3000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002'), 'JIT grant without expiry refused', 'permissions_jit_expiry');
SELECT spike_test.expect_error(format('INSERT INTO permissions (tenant_id, agent_id, tool_id, action_classes, grant_type, requested_by, approved_by) VALUES (%L, %L, %L, ARRAY[''read''], ''static'', %L, %L)', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a1000000-0000-0000-0000-000000000001', 'a3000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001'), 'grant approved by its requester refused', 'permissions_sod');
SELECT spike_test.expect_error(format('INSERT INTO mcp_servers (tenant_id, namespace, url) VALUES (%L, ''files'', ''https://dup.test'')', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'), 'duplicate namespace in a tenant refused', 'duplicate key');
COMMIT;

-- 6. Pooled connection: one connection serves tenant A, tenant B, then a request that sets nothing.
--    The tenant is set per transaction, so nothing carries over.
BEGIN; SELECT set_config('app.tenant_id', :a, true); SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT spike_test.expect_eq(:n, 2, 'request 1 (tenant A) sees its 2 tools');
BEGIN; SELECT set_config('app.tenant_id', :b, true); SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT spike_test.expect_eq(:n, 1, 'request 2 (tenant B) on the same connection sees its 1 tool');
BEGIN; SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT spike_test.expect_eq(:n, 0, 'request 3 (sets no tenant) sees nothing');
BEGIN; SELECT set_config('app.tenant_id', :a, true); SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT spike_test.expect_eq(:n, 2, 'request 4 (tenant A again) sees its 2 tools');
-- the setting is empty after commit, not stale
SELECT current_setting('app.tenant_id', true) AS leftover \gset
SELECT spike_test.expect_eq((:'leftover' = '')::int, 1, 'transaction-local setting is empty after the transaction, not stale');

-- 7. Why a session-level setting is forbidden: it leaks into the next request. DISCARD ALL clears it.
SELECT set_config('app.tenant_id', :a, false);
BEGIN; SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT spike_test.expect_eq(:n, 2, 'DEMONSTRATION: a session-level setting leaks tenant A into the next request');
RESET ROLE;
DISCARD ALL;
SET ROLE app_role;
BEGIN; SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT spike_test.expect_eq(:n, 0, 'DISCARD ALL on return to the pool removes the leaked setting');

-- 8. Empty string and garbage tenant values fail closed
BEGIN; SELECT set_config('app.tenant_id', '', true); SELECT count(*) AS n FROM tools \gset
COMMIT;
SELECT spike_test.expect_eq(:n, 0, 'empty tenant setting matches no rows');
BEGIN;
SELECT set_config('app.tenant_id', 'not-a-uuid', true);
SELECT spike_test.expect_error('SELECT count(*) FROM tools', 'malformed tenant setting errors instead of matching', 'invalid input syntax');
COMMIT;

-- 9. Role and table properties
RESET ROLE;
SELECT spike_test.expect_eq((SELECT count(*) FROM pg_roles WHERE rolname IN ('app_role', 'audit_writer') AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole)), 0, 'application roles are not superuser and have no BYPASSRLS, CREATEDB or CREATEROLE');
SELECT spike_test.expect_eq((SELECT count(*) FROM pg_class WHERE relname IN ('users','agents','mcp_servers','tools','tool_versions','approvals','permissions','scan_jobs','audit_events','tenants') AND relrowsecurity AND relforcerowsecurity), 10, 'row-level security is enabled and forced on all 10 tables');
SET ROLE app_role;
SELECT spike_test.expect_error('CREATE TABLE sneaky (i int)', 'application role cannot create tables', 'permission denied');
RESET ROLE;

\echo ALL CHECKS PASSED

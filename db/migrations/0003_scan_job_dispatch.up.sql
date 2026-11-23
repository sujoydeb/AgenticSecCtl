-- WP-1.7: a scanner worker has no tenant, yet must claim the next queued job whichever tenant it belongs to
-- (plan Section 5, IG-6). Row-level security stays on and nothing gets BYPASSRLS: one narrow role is allowed,
-- by an explicit policy on this one table, to see and update job rows across tenants, and only through the
-- columns it needs. It cannot read servers, tools, findings or anything else; after a claim the API continues
-- in the job's own tenant with the normal application role.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scan_dispatcher') THEN
    CREATE ROLE scan_dispatcher NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO scan_dispatcher;
GRANT EXECUTE ON FUNCTION current_tenant() TO scan_dispatcher;
GRANT SELECT (id, tenant_id, server_id, kind, status, claimed_by, lease_expires_at, attempts, max_attempts, created_at)
  ON scan_jobs TO scan_dispatcher;
GRANT UPDATE (status, claimed_by, lease_expires_at, attempts) ON scan_jobs TO scan_dispatcher;

CREATE POLICY dispatcher_all_tenants ON scan_jobs FOR ALL TO scan_dispatcher USING (true) WITH CHECK (true);

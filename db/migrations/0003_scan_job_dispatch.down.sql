-- Rollback of 0003. The role itself is cluster-wide and is left in place, like the roles of the baseline.
DROP POLICY IF EXISTS dispatcher_all_tenants ON scan_jobs;
REVOKE ALL ON scan_jobs FROM scan_dispatcher;
REVOKE EXECUTE ON FUNCTION current_tenant() FROM scan_dispatcher;
REVOKE USAGE ON SCHEMA public FROM scan_dispatcher;

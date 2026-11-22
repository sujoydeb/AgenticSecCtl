DROP TABLE IF EXISTS audit_events, scan_jobs, permissions, approvals, tool_versions, tools, mcp_servers, agents, users, tenants CASCADE;
DROP FUNCTION IF EXISTS current_tenant();
DROP FUNCTION IF EXISTS forbid_change();

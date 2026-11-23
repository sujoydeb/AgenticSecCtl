-- Rollback of 0001_baseline. Roles are cluster-wide and are left in place.
DROP TABLE IF EXISTS
  config_versions, retention_policies, control_mappings, controls, outbox, anchor_records,
  audit_chain_heads, audit_events, evidence_items, incident_assets, incidents, override_approvers,
  overrides, findings, scan_jobs, approvals, permissions, agent_server_allow, graph_edges,
  enterprise_systems, data_sources, tool_versions, scans, rule_sets, tools, server_egress_allow,
  mcp_servers, agents, models, classification_levels, role_bindings, users, tenants CASCADE;
DROP FUNCTION IF EXISTS audit_chain_link();
DROP FUNCTION IF EXISTS override_effect_check();
DROP FUNCTION IF EXISTS override_approver_check();
DROP FUNCTION IF EXISTS current_tenant();
DROP FUNCTION IF EXISTS forbid_change();

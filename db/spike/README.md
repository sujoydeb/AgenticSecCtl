# db/spike

Spike for checklist row P0-19 (`docs/governance.md` Section 8). **Not the product migration**: WP-1.5 writes that, starting from what this showed.

- `0001_core.up.sql` and `0001_core.down.sql`: the tenancy, row-level security and immutability parts of `docs/data-model.md` for ten tables (tenants, users, agents, MCP servers, tools, tool versions, approvals, permissions, scan jobs, audit events).
- `rls_tests.sql`: the checks, including the interleaved-tenant test on one connection (IG-9).
- `run.sh`: starts a throwaway `postgres:17-alpine` container, runs migration up, down and up again, then the checks. Needs Docker. It removes the container when it finishes.

Last run on 2026-11-22 against PostgreSQL 17.12: migration up, down and up again passed (32 relations, then 0, then 32), and every check passed. To confirm the checks can fail, two mutations were tried and each was caught: removing the `tool_versions` immutability trigger, and replacing the composite foreign key `(tenant_id, server_id)` with a plain one.

What it does not cover: the other tables of the data model, the audit hash chain, role passwords and connection pooling in a real pool (the pool is simulated by reusing one connection), performance, partitioning, and a superuser who disables triggers (the external anchors in `docs/data-model.md` Section 6 are the answer to that).

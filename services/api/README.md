# agenticsecctl-api

Management API and registry (control plane). Phase 1 subset, built in WP-1.5 and WP-1.6.

| Module | What it does |
|---|---|
| `migrate.py` | Migration runner for the plain SQL files in `db/migrations` (up, down, status; checksums; advisory lock; one transaction per migration) |
| `db.py` | The only way to get a connection: `Database.transaction(tenant)` sets `app.tenant_id` for that transaction only; the pool wipes session state on return |
| `registry.py` | Agents, servers (SSRF guard first), tool definitions (canonical JSON, hash, quarantine on change), approvals, separation of duties, Critical-finding overrides with two approvers |
| `events.py`, `audit.py` | Audit events through the outbox in the same transaction; the audit-writer role chains them (hash chain, per tenant) and verifies the chain |
| `roles_db.py` | Role bindings and users from the database for the common auth library |
| `app.py` | FastAPI routes under `/v1`: authenticate, authorize against the role table, require `Idempotency-Key`, then parse the body; refusals are audited; errors are problem details |

Dependencies are pinned with hashes in `requirements.lock` (runtime), `requirements-test.lock`, `requirements-dev.lock` (ruff and mypy, on top of the test lock) and `requirements-binary.lock`; regenerate with `python3 scripts/make_lock.py`. Install for development: `pip install --require-hashes -r requirements-dev.lock -r requirements-binary.lock`.

Run the tests (Docker needed):

```
PYTHONPATH=services/common/src:services/api/src python3 -m unittest discover -s services/api/tests
```

Not here yet: the scanner endpoints and job claim (WP-1.7), the gateway's event endpoint (WP-1.9), suspension, grants, incidents and evidence packs, a process entry point (no `uvicorn` run command yet).

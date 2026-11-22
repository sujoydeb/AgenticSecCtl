# AgenticSecCtl

Enterprise security gateway and governance platform for AI agents, MCP servers and MCP tools.

**Status:** design complete in draft, implementation not started. The directories below are an empty scaffold; nothing here builds or runs yet. The design documents in `Plan/` are the source of truth and are not modified by scaffolding.

## Layout

| Path | Purpose | Design reference |
|---|---|---|
| `Plan/` | Functional spec, architecture, threat model (do not restructure) | — |
| `services/common/` | Canonical hashing, audit hash chain, config, telemetry | architecture 4.8, spec FR-DRIFT-1, FR-AUD-* |
| `services/api/` | Management API and registry (control plane) | architecture 4.4 |
| `services/gateway/` | MCP gateway, PEP, interceptor pipeline (data plane) | architecture 4.1, 5 |
| `services/scanner/` | Scanning engine, hardened importer, SSRF guard | architecture 4.3, 4.5 |
| `policy/rego/`, `policy/tests/` | OPA policies and `opa test` suites | architecture 4.2, FR-POL-* |
| `web/` | React + TypeScript dashboard | architecture 4.11, FR-UI-* |
| `db/migrations/` | Postgres schema migrations | architecture 7 |
| `deploy/compose/` | Docker Compose for dev and CI end-to-end tests | architecture 8 |
| `deploy/helm/`, `deploy/k8s/`, `deploy/admission/` | Helm charts, NetworkPolicies, admission policies | architecture 8 |
| `controls/` | Control catalogue (versioned) | FR-COMP-1 |
| `compliance/` | Framework mapping matrix (mandatory / guidance / voluntary) | FR-COMP-2 |
| `tests/unit`, `integration`, `e2e`, `fuzz`, `adversarial` | Test suites; IDs follow `TC-*` in the threat model | threat model 7 |
| `tests/fixtures/evil_mcp/`, `benign_mcp/` | Hostile and benign MCP servers, run only on an isolated network | threat model 7 |
| `docs/testing/` | Test case catalogue (`cases.md`, 64 cases, not yet executed) | threat model 7 |
| `docs/runbooks/`, `docs/playbooks/` | Operational runbook, incident response playbooks | FR-IR-4 |
| `.github/workflows/` | CI security gates | NFR-9 |
| `scripts/` | Developer and CI helper scripts | — |

Each service is its own Python package (`src/` layout, Python >= 3.12) with a minimal `pyproject.toml` and no dependencies declared yet. Dependencies and tooling (linters, test runner) are added when the first code lands.

## Decisions still open

Gateway build-vs-extend, IdP, tenancy model, policy language and others are tracked as ADR-1..7 in `Plan/architecture.md` Section 12. The scaffold does not settle them.

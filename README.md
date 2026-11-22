# AgenticSecCtl

Enterprise security gateway and governance platform for AI agents, MCP servers and MCP tools.

**Status:** design complete in draft, implementation not started. The directories below are an empty scaffold; nothing here builds or runs yet. The design documents in `Plan/` are the source of truth. Run `python3 -I scripts/check_docs.py` after editing any document.

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
| `deploy/compose/` | Docker Compose for dev and CI end-to-end tests (not yet written; topology in `docs/deployment-architecture.md` Section 13) | architecture 8 |
| `deploy/helm/`, `deploy/k8s/`, `deploy/admission/` | Helm charts, NetworkPolicies, admission policies | architecture 8 |
| `controls/` | Control catalogue: `catalogue.yaml` (source) and `catalogue.md` (generated); 27 controls, CTL-01..27 | FR-COMP-1 |
| `compliance/` | Compliance mapping matrix (`compliance-matrix.md`: framework mappings and findings register; unverified, not legally reviewed) | FR-COMP-2..3 |
| `tests/unit`, `integration`, `e2e`, `fuzz`, `adversarial` | Test suites; IDs follow `TC-*` in the threat model | threat model 7 |
| `tests/fixtures/evil_mcp/`, `benign_mcp/` | Hostile and benign MCP servers, run only on an isolated network | threat model 7 |
| `docs/testing/` | Test case catalogue (`cases.md`, 65 cases, not yet executed) | threat model 7 |
| `docs/prd.md` | Product requirements document | — |
| `docs/tech-evaluation.md` | Technology evaluation (mostly unverified; has a verification log) | architecture 10, 12 |
| `docs/runbooks/` | Operational runbook (design-stage draft) | FR-OBS, NFR-3/4 |
| `docs/playbooks/` | Incident response playbooks (`incident-response-playbooks.md`, 15 scenarios, untested) | FR-IR-* |
| `.github/workflows/`, `.github/dependabot.yml` | `docs-check.yml` is the only active workflow (document consistency and generated-file freshness; untested on GitHub); Dependabot for action updates | NFR-9 |
| `docs/deployment-architecture.md` | Deployment architecture: environments, topology, network policy matrix, data tier, HA/DR, multi-tenancy, multi-cloud adapters, hardening, acceptance criteria (untested) | architecture 8, 9 |
| `docs/ci-cd-pipeline.md`, `docs/ci-templates/` | CI/CD security pipeline design (stages, gates, waivers, pipeline threats) and an inactive template for the product gates (action pins TBD) | NFR-9, CTL-17, CTL-27 |
| `scripts/` | `check_docs.py` (cross-document consistency checks), `build_spec_html.py` (regenerates `Plan/functional-spec.html`), `build_catalogue_md.py` and `catalogue_lib.py` (generate `controls/catalogue.md`) | — |

Each service is its own Python package (`src/` layout, Python >= 3.12) with a minimal `pyproject.toml` and no dependencies declared yet. Dependencies and tooling (linters, test runner) are added when the first code lands.

## Decisions still open

Gateway build-vs-extend, IdP, tenancy model, policy language and others are tracked as ADR-1..7 in `Plan/architecture.md` Section 12. The scaffold does not settle them.

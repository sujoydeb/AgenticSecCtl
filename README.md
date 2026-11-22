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
| `controls/` | Control catalogue: `catalogue.yaml` (source) and `catalogue.md` (generated); 30 controls, CTL-01..30 | FR-COMP-1 |
| `compliance/` | Compliance mapping matrix (`compliance-matrix.md`: framework mappings and findings register; unverified, not legally reviewed) | FR-COMP-2..3 |
| `tests/unit`, `integration`, `e2e`, `fuzz`, `adversarial` | Test suites; IDs follow `TC-*` in the threat model | threat model 7 |
| `tests/fixtures/evil_mcp/`, `benign_mcp/` | Hostile and benign MCP servers, run only on an isolated network | threat model 7 |
| `docs/testing/` | Test case catalogue (`cases.md`, 100 cases, not yet executed) | threat model 7 |
| `docs/prd.md` | Product requirements document | — |
| `docs/tech-evaluation.md` | Technology evaluation (mostly unverified; has a verification log) | architecture 10, 12 |
| `docs/runbooks/` | Operational runbook (design-stage draft) | FR-OBS, NFR-3/4 |
| `docs/playbooks/` | Incident response playbooks (`incident-response-playbooks.md`, 15 scenarios, untested) | FR-IR-* |
| `.github/workflows/`, `.github/dependabot.yml` | `docs-check.yml` is the only active workflow (document consistency and generated-file freshness; ran once on GitHub on 2026-11-22 and passed); Dependabot for action updates | NFR-9 |
| `docs/implementationgaps.md` | Review of the implementation plan: 17 gaps with severity, evidence and recommendation | implementation plan |
| `Plan/implementation-plan.md` | Build-level implementation plan: Phase 1 work packages, schedule, tests, definition of done; phases 2-5 outlined | roadmap Section 6 |
| `docs/roadmap.md` | Implementation roadmap: phases 0-5 with deliverables, dependencies, effort, acceptance, risks, decision gates, cross-document findings (estimates unvalidated) | PRD 8 |
| `docs/architecture-assessment.md`, `docs/data-model.md`, `docs/api-specification.md`, `docs/api/openapi.yaml` | Architecture assessment, data model and API specification (drafts closing review gaps A1 to A3) | architecture 7, spec 4.21 |
| `docs/governance.md`, `docs/reviewgap.md` | Governance templates (owners, reviews, decisions) and the review gap register with closure status | — |
| `docs/index.md` | Documentation index: reading paths by audience and the document map (checked for completeness) | — |
| `docs/mcp-compatibility.md`, `docs/authn-authz-design.md`, `docs/cross-cutting-design.md`, `docs/ux-outline.md` | MCP revision pin and compatibility matrix; authentication and authorization design with illustrative policy; logging, errors and configuration design; dashboard UX outline | spec 4.12, 4.6 |
| `docs/parameter-register.md`, `docs/privacy-assessment.md`, `docs/customer-inputs.md`, `docs/cloud-adapter-verification.md` | Fixed and open parameters (checked), platform privacy assessment, customer intake form, AWS adapter verification | NFR-*, deployment 12 |
| `docs/repository-setup.md` | Untested outline for remote repository and branch protection (not executed) | reviewgap G4 |
| `docs/testing/performance-test-plan.md`, `docs/testing/fixtures-and-corpora.md`, `tests/fixtures/corpus/` | Load-test environment and workload proposal; fixture and corpus specification; seed corpus (42 descriptions, 28 responses) | cases Section 1 |
| `docs/deployment-architecture.md` | Deployment architecture: environments, topology, network policy matrix, data tier, HA/DR, multi-tenancy, multi-cloud adapters, hardening, acceptance criteria (untested) | architecture 8, 9 |
| `docs/ci-cd-pipeline.md`, `docs/ci-templates/` | CI/CD security pipeline design (stages, gates, waivers, pipeline threats) and an inactive template for the product gates (action pins TBD) | NFR-9, CTL-17, CTL-27 |
| `scripts/` | `check_docs.py` (cross-document consistency checks), `build_spec_html.py` (regenerates `Plan/functional-spec.html`), `build_catalogue_md.py` and `catalogue_lib.py` (generate `controls/catalogue.md`), `validate_yaml.py` (optional YAML and OpenAPI validation; needs PyYAML), `sync_versions.py` (rewrites version citations after a bump) | — |

Each service is its own Python package (`src/` layout, Python >= 3.12) with a minimal `pyproject.toml` and no dependencies declared yet. Dependencies and tooling (linters, test runner) are added when the first code lands.

## Decisions still open

Gateway build-vs-extend, IdP, tenancy model, policy language and others are tracked as ADR-1..7 in `Plan/architecture.md` Section 12. The scaffold does not settle them.

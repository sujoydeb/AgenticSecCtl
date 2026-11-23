# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

AgenticSecCtl is an enterprise security gateway and governance platform for AI agents, MCP servers and MCP tools. The repository is currently **design-only with an empty code scaffold plus two spikes**: there is no product source code, build system or product test suite. The spikes are `policy/` (the Rego sketch, run under OPA, with 15 tests) and `db/spike/` (the core tables run on PostgreSQL, with 78 checks); both are evidence for Phase 0, not product code. The design lives in `Plan/` (core design documents) and `docs/` (supporting documents):

| File | Role | Version |
|---|---|---|
| `Plan/functional-spec.md` | Requirements (FR-*/NFR-*/AC-* IDs), roles, acceptance criteria, open decisions. Source of truth for *what* |v0.8 |
| `Plan/architecture.md` | Components, interceptor pipeline, sequences, deployment, ADRs, provisional audit event vocabulary (4.8). Source of truth for *how* |v0.6 |
| `Plan/threat-model.md` | Assets, adversaries, threats A–P and X1–X13, STRIDE, attack trees, TC index (Section 7), risk register | v0.5 |
| `Plan/functional-spec.html` | Styled HTML rendering of the functional spec, **generated** by `scripts/build_spec_html.py` | v0.7 |
| `docs/prd.md` | Product requirements: problem, personas, scope, release plan, metrics | v0.4 |
| `docs/testing/cases.md` | 100 security test cases (specifications, none executed) | v0.5 |
| `docs/tech-evaluation.md` | Reuse-vs-build evaluation; mostly unverified, has a verification log |v0.3 |
| `docs/runbooks/operational-runbook.md` | Operations procedures; placeholders marked `[TBD]` |v0.3 |
| `docs/implementationgaps.md` | Gap register for the implementation plan (IG-1..17; IG-1, IG-2, the five Low and the eight Medium gaps and IG-3 and IG-5 closed pending review (all 17 incorporated)) |v0.6 |
| `Plan/implementation-plan.md` | Build-level implementation plan (Phase 1 work packages WP-1.1..13, schedule, tests, definition of done; phases 2-5 outlined; generated traceability table of P1 requirements) |v0.7 |
| `docs/roadmap.md` | Enterprise implementation roadmap (phases 0-5), gates, spikes, allocation of requirements/controls/tests to phases, findings F1-F8; estimates unvalidated | v0.4 |
| `docs/architecture-assessment.md` | The first-task critical architecture assessment, traced to requirements, controls, tests and decisions | v0.3 |
| `docs/data-model.md` | Logical data model, constraints, roles, retention (illustrative SQL, unvalidated) |v0.3 |
| `docs/api-specification.md`, `docs/api/openapi.yaml` | Management API endpoints, roles, SoD, errors; OpenAPI 3.1 outline (unvalidated) |v0.2 |
| `docs/governance.md` | Role glossary, RACI, owner assignment, review/sign-off log, decision log, risk acceptance register (templates; no names yet), Phase 0 exit checklist | v0.6 |
| `docs/reviewgap.md` | Holistic review gap register (50 gaps) with a closure update for the 14 High gaps |v0.8 |
| `docs/index.md` | Reading guide by audience and the map of all design documents; every design document must be listed | v0.1 |
| `docs/mcp-compatibility.md` | MCP revision 2026-07-28 pin; authorization, transport and client-feature statements mapped to platform responses (pages read; others not) | v0.2 |
| `docs/authn-authz-design.md` | Flows, policy structure and decision contract; the Rego was run under OPA (spike draft in `policy/`) | v0.2 |
| `docs/cross-cutting-design.md` | Logging, error handling and configuration rules | v0.1 |
| `docs/ux-outline.md` | Dashboard information architecture and flows (no visual design) | v0.1 |
| `docs/parameter-register.md` | Fixed parameters (machine-checked) and open "to be set" parameters with owners and gates | v0.3 |
| `docs/privacy-assessment.md` | Platform data inventory and privacy risks; legal questions marked [LEGAL] | v0.2 |
| `docs/cloud-adapter-verification.md` | AWS and Azure adapter facts from documentation chunks; Google Cloud from search summaries only | v0.2 |
| `docs/decision-brief-phase0.md` | Decision brief for ADR-3, ADR-4 and ADR-6 with options, recommendations and conditions; nothing decided | v0.2 |
| `docs/repository-setup.md` | Outline for remote repository and branch protection; steps 1, 2, 9, 10 carried out on 2026-11-22, protection not configured | v0.3 |
| `docs/customer-inputs.md` | Blank customer intake form | v0.2 |
| `docs/testing/performance-test-plan.md`, `docs/testing/fixtures-and-corpora.md` | Proposed load-test environment and workload; fixture and corpus specification (seed corpus under `tests/fixtures/corpus/`) | v0.1 |
| `docs/deployment-architecture.md` | Deployment architecture refining architecture Section 8: topology, network policy matrix, data tier, HA/DR, tenancy models, adapters, DA-1..10 acceptance criteria; untested, many items unverified | v0.4 |
| `docs/ci-cd-pipeline.md` | CI/CD security pipeline design: 5 stages, gates mapped to requirements/controls/tests, waivers, pipeline threats; untested, tools unverified | v0.8 |
| `docs/playbooks/incident-response-playbooks.md` | Common IR phases and 15 scenario playbooks (PB-01..15); untested |v0.2 |
| `controls/catalogue.yaml` | **Source** of the control catalogue (CTL-01..30): how each control works, P/D/R/V, parameters, failure behaviour, false positives/negatives, bypass, residual risk |v0.6 |
| `controls/catalogue.md` | **Generated** readable catalogue; never edit by hand |v0.6 |
| `compliance/compliance-matrix.md` | Control-to-framework mapping by source type (mandatory/guidance/voluntary) and threat-level findings register; references controls by ID only; framework IDs unverified, not legally reviewed |v0.6 |

Phase 1 implementation has started (WP-1.1 to WP-1.8 and WP-1.10 in first form, stdlib only for Python, no dependencies pinned yet). `scripts/check_all.sh` runs the code checks (`scripts/check_code.py`: import boundaries, HTTP-client ban outside the guarded wrapper, secret scan) and the unittest suites (`tests/unit/`, `services/<pkg>/tests/`). Run a single package with `PYTHONPATH=services/common/src:services/common/src python3 -m unittest discover -s services/common/tests`. Done so far in `agenticsecctl_common`: RFC 8785 canonical JSON, tool-definition hash (IG-8), redaction, error catalogue; WP-1.3 SSRF guard and guarded client (`agenticsecctl_common/http/`, the only HTTP client allowed). Also done: typed configuration and telemetry bootstrap (WP-1.2), the audit chain, verifier and decision replay (WP-1.4: `auditchain.py`, `replay.py`, `contracts.py`; the in-memory `ChainWriter` is the model for the database-backed writer in the API), and the baseline schema (WP-1.5: `db/migrations/0001_baseline.{up,down}.sql`, tested by `db/tests/run.sh` against PostgreSQL in Docker: 126 relations, up/down/up, 82 checks). The chain-link trigger and the audit-writer role mean only `audit_writer` can write the chain and the database refuses gaps, forks and wrong previous hashes. Also done: token validation and identity (WP-1.10: `agenticsecctl_common/auth/`, pure-Python RS256 verification, key-set cache that fails closed, principals, roles and the endpoint role table checked against `docs/api-specification.md`; the development Keycloak realm is in `deploy/compose/keycloak/` and has not been started), and the Phase 1 policy and its bundle build (WP-1.8: `policy/rego/authz.rego`, `policy/build_bundle.py`). `python3 -I scripts/run_gate.py <WP> <title> -- <commands...>` runs a package gate and saves the output under `docs/testing/results/`. Also done: the migration runner (`agenticsecctl_api/migrate.py`, plain SQL files in `db/migrations`, PAR-O-27), tenant-per-transaction database access with psycopg 3 and a pool that wipes session state (`db.py`, PAR-O-28, IG-9), migration 0002 (the registry workflow columns), the registry service with approvals, separation of duties and overrides (`registry.py`), the outbox and the database-backed audit chain (`events.py`, `audit.py`), and the FastAPI management API for the registry subset (`app.py`). The api tests need Docker and the packages in `services/api/pyproject.toml` installed in the Python that runs them (the repository's `.venv`); `services/api/requirements.lock`, `requirements-test.lock` and `requirements-binary.lock` pin every dependency with the hash of every release file (generated by `python3 scripts/make_lock.py`, `--check` verifies they are current; install with `pip install --require-hashes -r ...`); the `python` job in `.github/workflows/docs-check.yml` installs only from them and runs `scripts/check_all.sh` (it has not run on GitHub yet). Also done (WP-1.7): the scanner (`services/scanner`: normaliser, deterministic rules, reproducible score, rule-set hash, advisory classifier stub, hardened importer, worker), the job lifecycle in the API (`jobs.py`, migration 0003, `/v1/internal/scan-jobs/*`, leases, attempts), a wall-clock deadline and a truncated-body check in the guarded client, and an isolation test that runs the worker in a container on a network containing only the API. `python3 scripts/measure_scanner.py` reports precision and recall on the three labelled sets; **recall is 100% on the development and held-out sets and 0 of 16 on the evasion set**, so a clean scan is never evidence of safety (see `services/scanner/README.md`). Integration tests live in `tests/integration` (Docker and PostgreSQL). Lint, type check and CI gates are not set up. The spikes and the schema tests need Docker (the schema tests run with `db/tests/run.sh`):

- `docker run --rm -v "$PWD/policy":/w -w /w openpolicyagent/opa:latest test rego tests` (also `check --strict` and `fmt --list`; see `policy/README.md`) runs the policy tests.
- `db/spike/run.sh` starts a throwaway `postgres:17-alpine` container, runs the migration up, down and up, then the row-level security checks (see `db/spike/README.md`).

### Document tooling

- `python3 -I scripts/check_docs.py` checks cross-document consistency (requirement/AC/ADR/TC references resolve, TC index equals catalogue, each control's phase in `controls/catalogue.yaml` equals the phases of the requirements it lists, `Depends on` version citations match actual versions, HTML parity, section references, stale phrases). Run it after any document edit; it must exit 0.
- `python3 -I scripts/build_spec_html.py Plan/functional-spec.md Plan/functional-spec.html` regenerates the HTML. Never edit the HTML by hand.
- `python3 -I scripts/sync_versions.py` rewrites the version citations in `Depends on` and `Companion` rows after you bump a document's version (`--check` only reports).
- Workflows: `.github/workflows/docs-check.yml` is the only active workflow; its `docs` job runs the document checks and its `spikes` job (Docker, images pinned by digest) runs the OPA tests and the PostgreSQL spike. `check_docs.py` enforces that active workflows declare `permissions`, pin third-party actions to a full commit SHA (or carry a `# waiver: W-nnn` comment recorded in `docs/ci-cd-pipeline.md` Section 7), and never use `pull_request_target`. The product gates live in `docs/ci-templates/product-security-gates.yml`, which is deliberately not a workflow (action pins are TBD); do not move it under `.github/workflows/` before the pins are verified.
- `scripts/validate_yaml.py` (needs PyYAML; run it with a Python that has PyYAML and openapi-spec-validator, for example a throwaway virtual environment outside the repo) parses every YAML file, cross-checks the stdlib catalogue loader and validates the OpenAPI outline; it is not part of `check_docs.py` because the repository stays stdlib-only.
- `python3 -I scripts/build_catalogue_md.py controls/catalogue.yaml controls/catalogue.md` regenerates the catalogue Markdown. `catalogue.yaml` uses a strict YAML subset (see `scripts/catalogue_lib.py`; PyYAML is not installed). `check_docs.py` fails if the Markdown is stale, if requirement, test, threat or control IDs do not resolve, or if the control IDs differ from compliance-matrix Section 3.

### Code scaffold (empty)

`README.md` has the full directory-to-design map. In short:

- `services/{common,api,gateway,scanner}/`: separate Python packages (`src/agenticsecctl_<name>`, Python >= 3.12, own `pyproject.toml`, no dependencies declared). Only a `__version__` string exists.
- `policy/{rego,tests}/` (only the spike policy and its tests), `db/spike/` (the PostgreSQL spike), `web/`, `db/migrations/`, `deploy/{compose,helm,k8s,admission}/`, `.github/workflows/` holds only `docs-check.yml`.
- `tests/{unit,integration,e2e,fuzz,adversarial}/` and `tests/fixtures/{evil_mcp,benign_mcp}/`: empty. Test IDs follow `TC-*` in the threat model.
- `docs/testing/`, `docs/runbooks/` and `docs/playbooks/` hold the catalogue, runbook and incident playbooks listed above.
- Keep the data-plane (`gateway`) and control-plane (`api`, `scanner`) packages independent; do not import across them except through `common`.

## Working on the documents

- **Traceability IDs are load-bearing.** Documents cross-reference by ID: `FR-<AREA>-n` / `NFR-n` / `AC-n` (spec), `F1..` boundary-crossing flows and `Z0..Z5` trust zones, threats `A`–`P` and `X1`–`X8`, test cases `TC-<threat><n>`, `ADR-n`, assumptions `A1..A4`, separation-of-duties rules `SoD-n`. When adding, renaming or renumbering any of these, update every reference: spec Section 5 (threat traceability incl. test cases) and Section 11 (AC mapping), architecture Section 11 (requirement-to-component), threat-model Section 7 (TC index) and `docs/testing/cases.md` (headings, header count, Section 20 coverage). Then run `scripts/check_docs.py`.
- **`[VERIFY]` marker** flags any vendor, product, library or protocol claim not yet checked against current documentation. Add it to new unverified claims; remove it only after actually verifying, and record the check in the verification log in `docs/tech-evaluation.md`.
- **"shall"** marks a mandatory requirement. FR rows carry priority (M/S/C), phase (P1 MVP, P2 runtime protection, P3 governance, P4 advanced threat protection, P5 enterprise production) and a verification method (UT, IT, E2E, PT, etc.). Rows tagged "added from runbook; review required" are new requirements awaiting owner review.
- **Version headers:** each document has a version table and a "Depends on" line naming the versions of the others. Bump these when a document changes materially, and update every `Depends on` that cites it (the check script verifies this). The spec keeps a change log (Section 0).
- **Single definitions:** the audit event vocabulary lives only in `Plan/architecture.md` Section 4.8; the test catalogue and runbook reference it. Document-control tables and `Companion` lines use paths relative to the file.
- **HTML is generated:** edit `functional-spec.md` only, then regenerate the HTML. It defines colors as CSS tokens with light/dark variants (kept in the generator); preserve that.
- Diagrams are Mermaid fenced blocks in markdown.
- `docs/testing/cases.md` is a specification only; no case has been executed. Requirements without a dedicated case are listed in its Section 21.

## Planned architecture (big picture)

Read `Plan/architecture.md` for detail. The essentials that span multiple sections:

- **Two separate planes.** Data plane: MCP Gateway (policy enforcement point), OPA (policy decision point) and egress proxy/SSRF guard. Control plane: management API and registry, scanner workers, audit service, React dashboard. A third zone holds the secrets/token broker, evidence vault and KMS. Planes have separate deployments, credentials and network paths. The control plane can change policy but cannot read raw evidence.
- **Every agent↔MCP server message crosses the gateway.** For `tools/call` the gateway runs a 14-stage, ordered, short-circuiting interceptor pipeline (architecture Section 5): transport, authN, registry check, tool-hash pin, limits, PDP decision, argument guards, request DLP, approval gate, brokered forward, response limits, injection/DLP inspection, taint labelling, audit.
- **Core invariants to preserve in any design or code:**
  - Deny by default and fail closed. Unknown entity, unreachable PDP or registry with expired cache, or stale policy bundle all mean deny.
  - Enforcement is deterministic. LLM or ML classifiers are advisory only and never the sole control for a high-impact action.
  - All MCP server content is untrusted, including from approved servers.
  - Approved tool definitions are stored as canonical JSON plus SHA-256 and are immutable. Any hash change quarantines the tool.
  - Every decision is reproducible from a stored policy hash and input digest. The audit log is a SHA-256 hash chain anchored externally. The chain is tamper-evident, not tamper-proof.
  - SSRF checks happen at every outbound connection (resolve-then-pin, redirect re-validation), not only at registration.
  - The gateway holds no long-lived upstream secrets; the broker mints short-lived, audience-bound credentials.
  - Separation of duties is enforced server-side: a requester or server owner cannot approve their own request.
- **Reuse before build.** OPA, the enterprise IdP, Presidio-style DLP, Syft/Grype/Trivy, cosign and the SIEM are integrated rather than reimplemented. Custom code is limited to MCP-aware control logic.

## Planned stack

Python 3.12+ with FastAPI and Pydantic, the official MCP Python SDK, PostgreSQL with row-level security, OPA/Rego, React + TypeScript, OpenTelemetry, Helm on Kubernetes. Keycloak for development identity. Redis, Kafka and the stdio wrapper arrive in Phase 2. Docker Compose is planned for dev and CI end-to-end tests, including hostile fixture MCP servers on an isolated network.

Open decisions are tracked as ADR-1..7 in architecture Section 12 and in spec Section 12. Notable ones: build vs extend the gateway, IdP choice, tenancy model, and Rego vs Cedar. Don't treat these as settled.

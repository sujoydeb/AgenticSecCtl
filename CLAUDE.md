# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

AgenticSecCtl is an enterprise security gateway and governance platform for AI agents, MCP servers and MCP tools. The repository is currently **design-only with an empty code scaffold**: there is no implemented source code, build system or test suite. The design lives in `Plan/` (core design documents) and `docs/` (supporting documents):

| File | Role | Version |
|---|---|---|
| `Plan/functional-spec.md` | Requirements (FR-*/NFR-*/AC-* IDs), roles, acceptance criteria, open decisions. Source of truth for *what* | v0.3 |
| `Plan/architecture.md` | Components, interceptor pipeline, sequences, deployment, ADRs, provisional audit event vocabulary (4.8). Source of truth for *how* | v0.2 |
| `Plan/threat-model.md` | Assets, adversaries, threats A–P and X1–X8, STRIDE, attack trees, TC index (Section 7), risk register | v0.2 |
| `Plan/functional-spec.html` | Styled HTML rendering of the functional spec, **generated** by `scripts/build_spec_html.py` | v0.3 |
| `docs/prd.md` | Product requirements: problem, personas, scope, release plan, metrics | v0.2 |
| `docs/testing/cases.md` | 65 security test cases (specifications, none executed) | v0.2 |
| `docs/tech-evaluation.md` | Reuse-vs-build evaluation; mostly unverified, has a verification log | v0.1 |
| `docs/runbooks/operational-runbook.md` | Operations procedures; placeholders marked `[TBD]` | v0.2 |
| `docs/ci-cd-pipeline.md` | CI/CD security pipeline design: 5 stages, gates mapped to requirements/controls/tests, waivers, pipeline threats; untested, tools unverified | v0.1 |
| `docs/playbooks/incident-response-playbooks.md` | Common IR phases and 15 scenario playbooks (PB-01..15); untested | v0.1 |
| `controls/catalogue.yaml` | **Source** of the control catalogue (CTL-01..27): how each control works, P/D/R/V, parameters, failure behaviour, false positives/negatives, bypass, residual risk | v0.1 |
| `controls/catalogue.md` | **Generated** readable catalogue; never edit by hand | v0.1 |
| `compliance/compliance-matrix.md` | Control-to-framework mapping by source type (mandatory/guidance/voluntary) and threat-level findings register; references controls by ID only; framework IDs unverified, not legally reviewed | v0.2 |

There are no build, lint or test commands for the product yet. When code is added, update this file with them.

### Document tooling

- `python3 -I scripts/check_docs.py` checks cross-document consistency (requirement/AC/ADR/TC references resolve, TC index equals catalogue, `Depends on` version citations match actual versions, HTML parity, section references, stale phrases). Run it after any document edit; it must exit 0.
- `python3 -I scripts/build_spec_html.py Plan/functional-spec.md Plan/functional-spec.html` regenerates the HTML. Never edit the HTML by hand.
- Workflows: `.github/workflows/docs-check.yml` is the only active workflow. `check_docs.py` enforces that active workflows declare `permissions`, pin third-party actions to a full commit SHA (or carry a `# waiver: W-nnn` comment recorded in `docs/ci-cd-pipeline.md` Section 7), and never use `pull_request_target`. The product gates live in `docs/ci-templates/product-security-gates.yml`, which is deliberately not a workflow (action pins are TBD); do not move it under `.github/workflows/` before the pins are verified.
- `python3 -I scripts/build_catalogue_md.py controls/catalogue.yaml controls/catalogue.md` regenerates the catalogue Markdown. `catalogue.yaml` uses a strict YAML subset (see `scripts/catalogue_lib.py`; PyYAML is not installed). `check_docs.py` fails if the Markdown is stale, if requirement, test, threat or control IDs do not resolve, or if the control IDs differ from compliance-matrix Section 3.

### Code scaffold (empty)

`README.md` has the full directory-to-design map. In short:

- `services/{common,api,gateway,scanner}/`: separate Python packages (`src/agenticsecctl_<name>`, Python >= 3.12, own `pyproject.toml`, no dependencies declared). Only a `__version__` string exists.
- `policy/{rego,tests}/`, `web/`, `db/migrations/`, `deploy/{compose,helm,k8s,admission}/`, `.github/workflows/` holds only `docs-check.yml`.
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

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

AgenticSecCtl is an enterprise security gateway and governance platform for AI agents, MCP servers and MCP tools. The repository is currently **design-only with an empty code scaffold**: there is no implemented source code, build system or test suite. The design lives in `Plan/` (do not restructure it):

| File | Role | Version |
|---|---|---|
| `Plan/functional-spec.md` | Requirements (FR-*/NFR-* IDs), roles, acceptance criteria, open decisions. Source of truth for *what* | v0.2 |
| `Plan/architecture.md` | Components, interceptor pipeline, sequences, deployment, ADRs. Source of truth for *how* | v0.1 |
| `Plan/threat-model.md` | Assets, adversaries, threats A–P and X1–X8, STRIDE, attack trees, test case IDs, risk register | v0.1 |
| `Plan/functional-spec.html` | Self-contained styled HTML rendering of the functional spec | v0.2 |

There are no build, lint or test commands yet. When code is added, update this file with them.

### Code scaffold (empty)

`README.md` has the full directory-to-design map. In short:

- `services/{common,api,gateway,scanner}/`: separate Python packages (`src/agenticsecctl_<name>`, Python >= 3.12, own `pyproject.toml`, no dependencies declared). Only a `__version__` string exists.
- `policy/{rego,tests}/`, `web/`, `db/migrations/`, `deploy/{compose,helm,k8s,admission}/`, `controls/`, `compliance/`, `scripts/`, `.github/workflows/`: empty (`.gitkeep`).
- `tests/{unit,integration,e2e,fuzz,adversarial}/` and `tests/fixtures/{evil_mcp,benign_mcp}/`: empty. Test IDs follow `TC-*` in the threat model.
- `docs/{testing,runbooks,playbooks}/`: empty. The threat model refers to `testing/cases.md`; the intended location is `docs/testing/cases.md`.
- Keep the data-plane (`gateway`) and control-plane (`api`, `scanner`) packages independent; do not import across them except through `common`.

## Working on the documents

- **Traceability IDs are load-bearing.** The three documents cross-reference each other by ID: `FR-<AREA>-n` / `NFR-n` (spec), `AC-n` acceptance criteria, `F1..` boundary-crossing flows and `Z0..Z5` trust zones, threats `A`–`P` and `X1`–`X8`, test cases `TC-<threat><n>`, `ADR-n`, assumptions `A1..A4`, separation-of-duties rules `SoD-n`. When adding, renaming or renumbering any of these, update every reference in all three files (spec Section 5 threat traceability, architecture Section 11 requirement-to-component table, threat-model Section 7 test index).
- **`[VERIFY]` marker** flags any vendor, product, library or protocol claim not yet checked against current documentation. Add it to new unverified claims; remove it only after actually verifying.
- **"shall"** marks a mandatory requirement. FR rows carry priority (M/S/C), phase (P1 MVP, P2 runtime protection, P3 governance, P4 advanced threat protection, P5 enterprise production) and a verification method (UT, IT, E2E, PT, etc.).
- **Version headers:** each document has a version table and a "Depends on" line naming the versions of the others. Bump these when a document changes materially; the spec keeps a change log (Section 0).
- **Keep the HTML in sync:** `functional-spec.html` is a hand-maintained copy of the markdown spec, not generated. Changes to `functional-spec.md` must be mirrored there. It defines colors as CSS tokens with light/dark variants; preserve that.
- Diagrams are Mermaid fenced blocks in markdown.
- `functional-spec.md` Section 3 still says the architecture document is "to be written"; it now exists.
- The threat model defers full test cases to `testing/cases.md`; the catalogue now exists at `docs/testing/cases.md` (64 cases, IDs match threat model Section 7). It is a specification only; no case has been executed. A known gap: AC-9 (log redaction) has no test case yet (see its Section 20). Adding or renumbering a `TC-*` ID means updating the threat-model index and that coverage table.

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

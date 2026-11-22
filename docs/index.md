# Documentation Index and Reading Guide

| | |
|---|---|
| Version | 0.1 (closes gap G7 in `docs/reviewgap.md`) |
| Depends on | `Plan/functional-spec.md` v0.7, `docs/governance.md` v0.4 |
| Purpose | Tell each reader which documents to read, in what order, and where every document lives. `scripts/check_docs.py` fails if a document is missing from the table in Section 2. |
| Status | All documents are drafts. Nothing has been independently reviewed (see `docs/governance.md`). Versions are in each document's header table, not repeated here. |

## 1. Reading paths by audience

| Audience | Read in this order |
|---|---|
| Sponsor, product owner | `docs/decision-brief-phase0.md`, `docs/prd.md`, `docs/roadmap.md`, `Plan/implementation-plan.md`, `docs/reviewgap.md` (Sections 1, 9, 10, 11), `docs/governance.md`, `docs/customer-inputs.md` |
| Security architect, reviewer | `docs/architecture-assessment.md`, `Plan/architecture.md`, `Plan/threat-model.md`, `controls/catalogue.md`, `docs/authn-authz-design.md`, `docs/reviewgap.md` |
| Backend and frontend engineers | `Plan/functional-spec.md` (Section 4), `Plan/architecture.md`, `docs/data-model.md`, `docs/api-specification.md`, `docs/cross-cutting-design.md`, `docs/mcp-compatibility.md`, `docs/ux-outline.md` |
| Platform and DevSecOps engineers | `docs/deployment-architecture.md`, `docs/cloud-adapter-verification.md`, `docs/ci-cd-pipeline.md`, `docs/runbooks/operational-runbook.md`, `docs/parameter-register.md` |
| Test engineers | `docs/testing/cases.md`, `docs/testing/fixtures-and-corpora.md`, `docs/testing/performance-test-plan.md`, `Plan/threat-model.md` Section 7 |
| Operators and incident responders | `docs/runbooks/operational-runbook.md`, `docs/playbooks/incident-response-playbooks.md`, `docs/governance.md` |
| Compliance, privacy, legal, auditors | `compliance/compliance-matrix.md`, `docs/privacy-assessment.md`, `controls/catalogue.md`, `docs/testing/cases.md` (Section 20), `docs/reviewgap.md` |
| Anyone contributing documents | `CLAUDE.md` (rules for traceability IDs, versions, generated files), `README.md` (repository layout), `docs/parameter-register.md` |

## 2. Document map

| Path | Purpose | Main readers |
|---|---|---|
| `Plan/architecture.md` | Components, trust zones, request pipeline, sequences, deployment summary, ADRs | Architects, engineers |
| `Plan/functional-spec.md` | Requirements (what the platform shall do), roles, acceptance criteria, open decisions | Everyone; source of truth for IDs |
| `Plan/threat-model.md` | Assets, adversaries, threats, attack trees, exclusions, test index, risk register | Security, architects, test |
| `docs/repository-setup.md` | Untested outline for creating the remote repository and applying branch protection (nothing executed) | Delivery lead, DevSecOps |
| `compliance/compliance-matrix.md` | Control-to-framework mapping by source type; findings register; not legally reviewed | Compliance, auditors |
| `controls/catalogue.md` | Generated readable control catalogue; source is `controls/catalogue.yaml` | Security, auditors, engineers |
| `docs/api-specification.md` | Management API endpoints, roles, errors, traceability | Backend and frontend engineers |
| `docs/architecture-assessment.md` | Critical architecture assessment: missing vectors, weak assumptions, reuse, trade-offs | Architects, reviewers |
| `docs/authn-authz-design.md` | Authentication and authorization flows, policy structure, illustrative Rego | Security engineers, backend |
| `docs/ci-cd-pipeline.md` | CI/CD security pipeline stages, gates, waivers, pipeline threats | DevSecOps, engineers |
| `docs/cloud-adapter-verification.md` | AWS adapter facts verified from documentation; other clouds pending | Platform engineers |
| `docs/cross-cutting-design.md` | Logging, errors and configuration rules | Engineers, operators |
| `docs/customer-inputs.md` | Blank intake form for customer decisions | Product, customer |
| `docs/data-model.md` | Logical data model, constraints, roles, retention (illustrative SQL) | Backend engineers, DBAs |
| `docs/deployment-architecture.md` | Environments, topology, network policy, data tier, availability, tenancy, adapters | Platform engineers, security |
| `docs/governance.md` | Roles, RACI, owners, review log, decision log, risk acceptance (templates); Phase 0 exit checklist | Sponsor, owners, reviewers |
| `docs/decision-brief-phase0.md` | Decision brief for ADR-3, ADR-4 and ADR-6 (options, recommendation, conditions) | Sponsor, security architect, product owner |
| `docs/mcp-compatibility.md` | MCP revision pin and compatibility matrix | Gateway engineers, security |
| `docs/parameter-register.md` | Fixed (checked) and open parameters with owners and gates | Everyone changing values |
| `docs/playbooks/incident-response-playbooks.md` | Incident phases, severity model, 15 scenario playbooks | Incident responders |
| `docs/prd.md` | Problem, personas, scope, release plan, metrics, risks | Product, sponsors |
| `docs/privacy-assessment.md` | Platform data inventory and privacy risks | Privacy, legal, security |
| `docs/reviewgap.md` | Review gap register with closure status | Reviewers, sponsors |
| `docs/roadmap.md` | Phases 0 to 5: deliverables, effort, acceptance, risks, spikes, gates | Sponsors, delivery |
| `docs/implementationgaps.md` | Gaps and errors found in the implementation plan (17 gaps, none closed) | Delivery lead, architects |
| `Plan/implementation-plan.md` | Build-level plan: Phase 1 work packages, schedule, test strategy, definition of done; later phases outlined | Engineers, delivery lead |
| `docs/runbooks/operational-runbook.md` | Operating procedures, failure responses, break-glass, disaster recovery | Operators, on-call |
| `docs/tech-evaluation.md` | Reuse-versus-build candidates and verification log | Architects, security |
| `docs/testing/cases.md` | Security test cases (specifications) | Test engineers, security |
| `docs/testing/fixtures-and-corpora.md` | Fixture servers, harness requirements, detector corpus format and rules | Test engineers, security |
| `docs/testing/performance-test-plan.md` | Proposed load-test environment, workload, pass criteria | Test engineers, platform |
| `docs/ux-outline.md` | Dashboard information architecture and flows | Product, design, frontend |

Not listed here because they are not design documents: `README.md` (repository overview), `CLAUDE.md` (guidance for automated assistants and contributors), the service stubs under `services/`, and the seed-corpus note under `tests/fixtures/corpus/`. Machine-readable sources: `controls/catalogue.yaml` (source of `controls/catalogue.md`), `docs/api/openapi.yaml`, `Plan/functional-spec.html` (generated from the specification).

## 3. How the documents depend on each other

1. `Plan/functional-spec.md` defines requirement IDs; every other document refers to them.
2. `controls/catalogue.yaml` defines controls (CTL-nn) that implement requirements; `compliance/compliance-matrix.md` maps controls to frameworks.
3. `Plan/threat-model.md` defines threats and the test-case index; `docs/testing/cases.md` defines the cases.
4. `Plan/architecture.md` and `docs/deployment-architecture.md` describe components and deployment; `docs/data-model.md` and `docs/api-specification.md` detail the build.
5. Operations (`docs/runbooks/...`, `docs/playbooks/...`) and delivery (`docs/roadmap.md`, `docs/ci-cd-pipeline.md`) build on all of the above.
6. `docs/reviewgap.md` records what is still missing; `docs/governance.md` records who must decide and review.

## 4. Rendering

Only the specification has a rendered form (`Plan/functional-spec.html`, generated). The other documents are Markdown; diagrams are Mermaid blocks that render in common Markdown viewers. Rendering the other documents to HTML is not done (the converter in `scripts/build_spec_html.py` supports only the Markdown subset used by the specification).

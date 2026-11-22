# Documentation Governance: owners, reviews and decisions

| | |
|---|---|
| Version | 0.3 (template; **no owner, reviewer or approval below is real until a person's name and date are entered**) |
| Depends on | `Plan/functional-spec.md` v0.7 (Section 2 roles, Section 12), `Plan/architecture.md` v0.5 (Section 12 ADRs), `controls/catalogue.md` v0.5 (owner roles), `docs/prd.md` v0.4, `docs/roadmap.md` v0.4, `docs/reviewgap.md` v0.6 |
| Purpose | Provide the structure needed to close gaps F2 (no named owners) and G1 (no independent review) in `docs/reviewgap.md`: role glossary and RACI, owner assignment table, review and sign-off log, decision log and risk-acceptance register. It does **not** close those gaps by itself: they close when people fill it in. |

## 1. Role glossary

Three layers, so documents stop mixing role names.

| Layer | Roles | Source |
|---|---|---|
| Platform roles (what a person may do in the product) | Viewer, Agent owner, Server owner, Security engineer, Approver, Security admin, Auditor, Incident responder, Platform operator | Spec Section 2 |
| Operational roles (who does what during operations and incidents) | Platform on-call, Security on-call, Incident commander, Scribe, Communications lead, Service owner, Compliance liaison, Legal/privacy | Runbook Section 3; playbooks Section 2 |
| Governance roles (who owns documents, decisions and risks) | Sponsor, Product owner, Security architect, Delivery lead, Test lead, Control owner (role-based), Risk owner, Independent reviewer | This document |

Mapping of the old control-catalogue owner strings to the glossary (adopted in catalogue v0.3; the catalogue now uses only the glossary roles on the right, with security specialties such as identity or platform security expressed through the control description, not the role name):

| Catalogue owner string | Glossary role |
|---|---|
| Security engineering | Security engineer (platform role) under the Security architect |
| Platform security | Security engineer with Platform operator |
| Identity and access team | Security engineer (identity specialty) |
| Business owner and approver pool | Approver |
| Data protection / security engineering; Data protection / platform ops | Compliance liaison with Security engineer or Platform operator |
| Security operations; Security operations / audit liaison | Security on-call; Auditor liaison |
| Incident commander / security operations | Incident commander |
| AI governance / model owner | Product owner with Agent owner |
| Security administration | Security admin |
| Platform operations | Platform operator |
| Compliance liaison | Compliance liaison |
| Engineering management / platform security | Delivery lead with Security engineer |

## 2. RACI for key activities

R responsible, A accountable (one per row), C consulted, I informed.

| Activity | Sponsor | Product owner | Security architect | Delivery lead | Test lead | Compliance liaison | Platform operator | Independent reviewer |
|---|---|---|---|---|---|---|---|---|
| Approve design documents | A | R | R | C | C | C | C | R |
| Decide an ADR | I | A | R | C | I | C | C | I |
| Maintain requirements and traceability | I | A | R | C | C | I | I | I |
| Maintain control catalogue | I | I | A | C | C | C | I | I |
| Verify unverified claims | I | C | A | R | I | C | C | C |
| Legal review of compliance mapping | I | C | C | I | I | A | I | R |
| Test catalogue and fixtures | I | C | C | C | A | I | I | I |
| Operational runbook and playbooks | I | I | C | C | C | C | A | R |
| Accept residual risk | A | R | R | I | I | C | I | I |
| Release gate (phase go/no-go) | A | R | R | R | R | C | C | C |

## 3. Owner assignment (to be filled)

| Item | Role | Name | Date assigned |
|---|---|---|---|
| Sponsor | Sponsor | *(open)* | |
| Product owner (PRD owner) | Product owner | *(open)* | |
| Security architect | Security architect | *(open)* | |
| Delivery lead | Delivery lead | *(open)* | |
| Test lead | Test lead | *(open)* | |
| Compliance liaison | Compliance liaison | *(open)* | |
| Legal and privacy contact | Legal/privacy | *(open)* | |
| Independent reviewer(s) | Independent reviewer | *(open)* | |
| Control owners (one per control CTL-01..30) | Control owner | *(open; role names in the catalogue)* | |
| Risk owners (one per residual risk in `Plan/threat-model.md` Section 8) | Risk owner | *(open)* | |

## 4. Review and sign-off log

One row per document; add rows per review round. A document is "reviewed" only when a reviewer who did not write it records a date and outcome. Current status for all documents: **not reviewed**.

| Document | Version | Reviewer (not the author) | Review date | Outcome (approved, approved with changes, rejected) | Open items |
|---|---|---|---|---|---|
| `Plan/functional-spec.md` | 0.5 | *(open)* | | | |
| `Plan/architecture.md` | 0.4 | *(open)* | | | |
| `Plan/threat-model.md` | 0.4 | *(open)* | | | |
| `docs/testing/cases.md` | 0.4 | *(open)* | | | |
| `Plan/implementation-plan.md` | 0.1 | *(open)* | | | |
| `controls/catalogue.yaml` | 0.3 | *(open; compare YAML source)* | | | |
| `compliance/compliance-matrix.md` | 0.4 | *(open; legal/compliance required)* | | | |
| `docs/architecture-assessment.md` | 0.2 | *(open)* | | | |
| `docs/data-model.md` | 0.1 | *(open)* | | | |
| `docs/api-specification.md` and `docs/api/openapi.yaml` | 0.1 | *(open)* | | | |
| `docs/authn-authz-design.md` | 0.1 | *(open)* | | | |
| `docs/cross-cutting-design.md` | 0.1 | *(open)* | | | |
| `docs/ux-outline.md` | 0.1 | *(open)* | | | |
| `docs/mcp-compatibility.md` | 0.1 | *(open)* | | | |
| `docs/privacy-assessment.md` | 0.1 | *(open; privacy and legal required)* | | | |
| `docs/deployment-architecture.md` | 0.3 | *(open)* | | | |
| `docs/cloud-adapter-verification.md` | 0.1 | *(open)* | | | |
| `docs/ci-cd-pipeline.md` | 0.3 | *(open)* | | | |
| `docs/runbooks/operational-runbook.md` | 0.3 | *(open; operations)* | | | |
| `docs/playbooks/incident-response-playbooks.md` | 0.2 | *(open; incident commander)* | | | |
| `docs/tech-evaluation.md` | 0.2 | *(open)* | | | |
| `docs/testing/performance-test-plan.md` | 0.1 | *(open)* | | | |
| `docs/testing/fixtures-and-corpora.md` | 0.1 | *(open)* | | | |
| `docs/parameter-register.md` | 0.1 | *(open)* | | | |
| `docs/customer-inputs.md` | 0.1 | *(open; customer)* | | | |
| `docs/index.md` | 0.1 | *(open)* | | | |
| `docs/prd.md` | 0.3 | *(open)* | | | |
| `docs/roadmap.md` | 0.3 | *(open)* | | | |

## 5. Decision log

| ID | Decision | Proposed resolution (from `Plan/architecture.md` Section 12) | Status | Decided by | Date |
|---|---|---|---|---|---|
| ADR-1 | Gateway build or extend | Custom thin gateway for MVP; Phase 2 base after spike S1 | Proposed, pending approval | | |
| ADR-2 | Identity provider and token binding | Keycloak for development; production IdP after spike S2 | Proposed, pending approval | | |
| ADR-3 | Approval channel | Dashboard queue first | Proposed, pending approval | | |
| ADR-4 | Tenancy model | Shared multi-tenant with row-level security | Proposed, pending approval | | |
| ADR-5 | Stdio server handling | Managed wrapper | Proposed, pending approval | | |
| ADR-6 | Policy language | Rego on OPA | Proposed, pending approval | | |
| ADR-7 | Audit anchoring target | Object-lock storage in a separate account | Proposed, pending approval | | |
| DEC-1 | Data classification default levels | Public, Internal, Confidential, Restricted; unlabelled = Confidential (spec Section 4.22) | Proposed, pending approval | | |
| DEC-2 | Phase-tag resolutions for review gap C1 | As recorded in spec change log v0.4 and test catalogue v0.3 | Proposed, pending approval | | |
| DEC-3 | Single incident severity model with operational and security dimensions (higher wins) | Playbooks Section 3; runbook Section 3 refers to it | Proposed, pending approval | | |
| DEC-4 | Emergency policy scope (FR-AUTO-6) | Relax only the different-approver rule of FR-AUTO-5 | Proposed, pending approval | | |
| DEC-5 | Key management requirements (FR-KEY-1..6) and control CTL-30 | As in spec Section 4.23 | Proposed, pending approval | | |
| DEC-6 | Control owner vocabulary | Glossary roles only (catalogue v0.3) | Proposed, pending approval | | |
| DEC-7 | Reference environment and workload for performance tests | `docs/testing/performance-test-plan.md` | Proposed, pending approval | | |
| DEC-8 | Spike schedule before Phase 1 | `docs/roadmap.md` Section 4.1 | Proposed, pending approval | | |
| DEC-9 | Placeholder retention default (13 months hot, 7 years cold) | Replace after legal input (parameter PAR-F-06) | Open, needs legal | | |
| DEC-10 | Governance of additional high-impact classes and the critical resource tag | Security admin plus a different approver, shadow mode first (FR-AUTHZ-12) | Proposed, pending approval | | |

## 6. Risk acceptance register

Residual risks that the design accepts must be accepted by a named risk owner with an expiry. Template:

| Risk (threat ID, residual statement) | Owner | Accepted until | Compensating controls | Review trigger |
|---|---|---|---|---|
| X2: unmanaged endpoints bypass the gateway | *(open)* | | Discovery, reporting, egress controls (CTL-26, CTL-08) | New endpoint class appears |
| D: probabilistic injection detection | *(open)* | | Taint rule, approvals, egress allowlists (CTL-09, CTL-07) | Detector quality below budget |
| G: replay window when sender-constrained tokens are unavailable | *(open)* | | Short lifetimes, revocation, mTLS (CTL-05, CTL-04) | IdP decision (ADR-2) |
| J: memory poisoning before Phase 4 | *(open)* | | Partial controls only | Phase 4 start |

## 7. Maintenance

Update this file whenever a document version changes, a review happens, an ADR is decided or a risk is accepted. `scripts/check_docs.py` verifies that version citations in `Depends on` lines match actual versions; it does not check this file's content, so a person must keep the tables current.

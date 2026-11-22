# Documentation Governance: owners, reviews and decisions

| | |
|---|---|
| Version | 0.4 (adds the Phase 0 exit checklist, Section 8; template; **no owner, reviewer or approval below is real until a person's name and date are entered**) |
| Depends on | `Plan/functional-spec.md` v0.7 (Section 2 roles, Section 12), `Plan/architecture.md` v0.5 (Section 12 ADRs), `controls/catalogue.md` v0.5 (owner roles), `docs/prd.md` v0.4, `docs/roadmap.md` v0.4, `docs/reviewgap.md` v0.7 |
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

## 8. Phase 0 exit checklist

The itemised form of the Phase 0 exit criteria in `docs/roadmap.md` Section 5 and the entry conditions in `Plan/implementation-plan.md` Sections 3, 8.1 and 12. **Every status below is Open: nothing has been decided, assigned or reviewed.** Owners are roles from Section 1; the due weeks are proposals counted backwards from the start of Phase 1 (week 0), matching the spike schedule in `docs/roadmap.md` Section 4.1.

"Needed by" is **Start** (closed before Phase 1 begins) or the work package that cannot begin or finish without it. Phase 1 starts when every **Start** row is closed or carries an approved, time-boxed waiver in Section 6; a package-gated row that is still open when its package starts stops that package, not the others.

| ID | Item | Owner role | Evidence that closes it | Due | Needed by | Status |
|---|---|---|---|---|---|---|
| **People and ownership** | | | | | | |
| P0-01 | Name the holders of Sponsor, Product owner, Security architect, Delivery lead, Test lead, Compliance liaison and Legal/privacy contact | Sponsor | Section 3 filled with names and dates | Week -6 | Start | Open |
| P0-02 | Name at least one independent reviewer who wrote none of the documents under review | Sponsor | Section 3 row filled; reviewer has accepted | Week -6 | Start | Open |
| P0-03 | Confirm the team (two backend engineers, a security engineer, part-time frontend and DevSecOps engineers) and name one engineer per lane | Delivery lead | Lane table of the plan (Section 6.3) with names; capacity gaps and the slip order accepted | Week -2 | Start | Open |
| P0-04 | Name risk owners for the residual risks that matter in Phase 1 (threat classes A, B, C, E, F, G, H) | Security architect | Section 6 rows filled | Week -2 | Start | Open |
| **Review** | | | | | | |
| P0-05 | Independent review of the Phase 1 inputs: functional spec, architecture, threat model, implementation plan, data model, API specification, authentication and authorization design, cross-cutting design, test catalogue, roadmap, parameter register and this document | Independent reviewer | One row per document in Section 4 with reviewer, date and outcome; every finding fixed, accepted or waived | Week -1 | Start | Open |
| P0-06 | Resolve or accept the cross-document findings F1 to F8 of `docs/roadmap.md` Section 9 | Delivery lead | Each finding marked resolved or accepted with a reason | Week -1 | Start | Open |
| **Decisions** | | | | | | |
| P0-07 | ADR-4 tenancy model decided | Security architect, with Sponsor | Section 5 row decided, with name and date | Week -2 | Start (schema freeze at the end of week 2) | Open |
| P0-08 | ADR-3 approval channel decided | Product owner | Section 5 row decided | Week -1 | Start | Open |
| P0-09 | ADR-6 policy language decided, after the S3 result | Security architect | Section 5 row decided | Week -3 | Start | Open |
| P0-10 | ADR-1, ADR-2, ADR-5 and ADR-7 scheduled, each with an owner and a date (not decided now) | Delivery lead | Section 5 rows carry owner and date | Week -1 | Start | Open |
| P0-11 | DEC-1 (classification levels), DEC-2 and DEC-8 decided | Product owner | Section 5 rows decided | Week -2 | WP-1.5 | Open |
| P0-12 | Design notes of plan Section 4.4 (upstream forwarding, audit path) confirmed or changed at review checkpoint R1 | Security architect, with the independent reviewer | Outcome recorded in Section 4; plan updated if changed | Week -1 | WP-1.4, WP-1.9 | Open |
| P0-13 | Hashed definition fields decided: FR-DRIFT-1 lists six fields, the plan and `docs/mcp-compatibility.md` Section 3A hash eight; the spec or the plan changed so they agree | Security engineer decides; spec owner edits | Spec change-log entry or plan change; `check_docs.py` passes | Week -2 | WP-1.2 | Open |
| P0-14 | `Plan/architecture.md` Section 4.8 aligned with the Phase 1 audit design (chain writer inside `api`, event name for audit gaps added to the vocabulary) | Security architect | Architecture version bumped; plan open item closed | Week -2 | WP-1.4 | Open |
| **Spikes and verification** | | | | | | |
| P0-15 | Spike S5 (scanner baselines) done | Security engineer | Detection overlap table, false positives, data-egress notes (roadmap Section 4.1) | Weeks -6 to -5 | WP-1.7 design | Open |
| P0-16 | Spike S3 (policy latency) done, including running the illustrative Rego with `opa test` | Backend engineer | Latency numbers against NFR-1, cache design, test output | Weeks -5 to -4 | WP-1.8 design | Open |
| P0-17 | Spikes S1, S2, S4 and S6 scheduled with owners and windows (run before Phase 2, not before Phase 1) | Delivery lead | Dates in the roadmap spike table | Week -1 | Start | Open |
| P0-18 | `[VERIFY]` items that Phase 1 depends on checked and logged: MCP SDK support for revision 2026-07-28, OPA, Keycloak, PostgreSQL row-level security with pooling, the Python libraries of plan Section 4.3 | Security architect | Entries in the verification log of `docs/tech-evaluation.md` | Week -2 | Pinning of each dependency | Open |
| P0-19 | Data-model SQL for tenancy, row-level security and immutability run on a real PostgreSQL instance (including the interleaved-tenant test of IG-9), and `docs/api/openapi.yaml` validated with a tool | Backend engineer | Test output attached; data model and API documents updated | Week -3 | Schema freeze (WP-1.5) | Open |
| **Parameters** | | | | | | |
| P0-20 | Values proposed and recorded for the open parameters with gate B1: PAR-O-01, PAR-O-02, PAR-O-03, PAR-O-04, PAR-O-05, PAR-O-06, PAR-O-07, PAR-O-25, PAR-O-27 and PAR-O-28. PAR-O-26 and PAR-O-29 are decided during Phase 1, before their packages | Owners named in `docs/parameter-register.md` | Register rows moved to Section 1 of the register where decided, or an owner and date recorded | Week -1 | The package that uses each (PAR-O-27 and PAR-O-28: WP-1.5) | Open |
| **Repository and customer input** | | | | | | |
| P0-21 | Repository controls in place and observed working: CODEOWNERS with real names for `common`, `policy/` and `db/migrations/` (review rule R2), branch protection requiring `docs-check`, and plan availability for a private repository checked | Delivery lead, with the DevSecOps engineer | Steps 3 to 6 of `docs/repository-setup.md` observed; Section 4 of that document updated | Week -1 | Start | Open |
| P0-22 | Customer answers CI-1 to CI-15 collected, or the working assumptions confirmed or replaced, at least for those named in plan Section 3 | Product owner | `docs/customer-inputs.md` filled or assumptions signed | Week -2 | Start | Open |
| **Gate** | | | | | | |
| P0-23 | Estimates re-baselined after the spikes: 15 to 20 percent buffer added, lane overruns resolved, Phase 1 dates committed | Delivery lead | Updated plan Sections 6.1 and 6.3; roadmap Section 8 updated | Week -1 | Start | Open |
| P0-24 | Go or no-go decision recorded with approvers who are not the delivery lead alone | Sponsor | Decision log row; evidence attached to the review log; Phase 0 marked complete in the roadmap | Week -1 | Start | Open |

`scripts/check_docs.py` checks that every parameter with gate B1 in `docs/parameter-register.md` is named in row P0-20.

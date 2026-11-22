# Review Gap Register: AgenticSecCtl documentation set

| | |
|---|---|
| Version | 0.4 (adds closure updates for High gaps (Section 9), Medium gaps (Section 10) and Low gaps (Section 11); Sections 1 to 8 still describe the register as first written, at the document versions listed) |
| Date | 2026-11-22 |
| Scope | All hand-written Markdown documents in `Plan/`, `docs/`, `compliance/`, plus `CLAUDE.md`, `README.md`, and `controls/catalogue.yaml` (source of `controls/catalogue.md`) |
| Documents and versions reviewed | `Plan/functional-spec.md` v0.3, `Plan/architecture.md` v0.2, `Plan/threat-model.md` v0.2, `docs/testing/cases.md` v0.2, `docs/prd.md` v0.2, `docs/runbooks/operational-runbook.md` v0.2, `docs/playbooks/incident-response-playbooks.md` v0.1, `compliance/compliance-matrix.md` v0.2, `controls/catalogue.md` v0.1, `docs/ci-cd-pipeline.md` v0.1, `docs/deployment-architecture.md` v0.1, `docs/roadmap.md` v0.1, `docs/tech-evaluation.md` v0.1 |
| Method | Scripted traceability checks (requirement, control, test, threat, phase) plus cross-document reading against the master brief; see Section 2 |
| Effect on other files | Version 0.1 changed no other document. The closure work recorded in Section 9 changed many (specification, threat model, architecture, test catalogue, control catalogue, compliance matrix, tech evaluation, roadmap and others) and added new documents; Section 9 lists them |

## 1. Executive summary

The documentation set is mechanically consistent: every requirement, control, test, threat and architecture-decision identifier resolves, the generated files are current, and the consistency checker passes. It is **not** yet a sound basis for implementation sign-off, for four reasons: nothing has been independently reviewed (G1); the claims about products, protocols, clouds and regulations are unverified (E1 to E4); the first-task architecture assessment and the build-level specifications (data model, API, authorization policies) are missing (A1 to A4); and there are traceability and phase contradictions that a gate review would trip over (B1 to B3, C1).

**50 gaps** across eight categories: Critical 0, High 14, Medium 29, Low 7.

| Category | Gaps |
|---|---|
| A. Coverage against the master brief | 8 |
| B. Traceability | 6 |
| C. Cross-document inconsistencies | 6 |
| D. Undefined or underspecified terms and parameters | 7 |
| E. Unverified claims and placeholders | 7 |
| F. Open decisions and missing inputs | 4 |
| G. Process, tooling and assurance | 7 |
| H. Security substance | 5 |

No gap is rated Critical because nothing is deployed and no control is claimed to be operating; the High items are those that would block or mislead the next gate (Phase 0 sign-off, Phase 1 start, Phase 2 start).

**Ten gaps to close first**

1. **F2** (High): No named owners: the PRD owner is unassigned, control owners are roles only, risk owners are blank, there are no document reviewers, and no team, budget or cost model exists.
2. **G1** (High): No independent review or sign-off of any document.
3. **F1** (High): ADR-3 (approval channel), ADR-4 (tenancy) and ADR-6 (policy language) gate Phase 1 and are open.
4. **A1** (High): The brief's first task, a critical architecture assessment (missing attack vectors, weak assumptions, architectural gaps, reuse list, deterministic versus LLM-based controls, bottlenecks, regulatory and operational risks), is not a document in the repository.
5. **C1** (High): Phase tags conflict between test cases and the requirements they exercise, and between design documents: TC-B2 (P1) uses FR-RT-2 (P2); TC-K1 (P2) uses FR-ID-5 (P4); TC-L3 (P3) uses FR-SCAN-5 (P4); TC-O1 (P2) uses FR-EXEC-1 (P4).
6. **B1** (High): 11 of 115 requirements are implemented by no control in the catalogue: FR-SCAN-7, FR-SCAN-8, FR-RT-1, FR-UI-1, FR-UI-2, FR-UI-3, FR-UI-4, FR-UI-5, FR-UI-6, FR-ADM-1, FR-ADM-3.
7. **B2** (High): 9 requirements have no test case at all, directly or through a control: FR-SCAN-7, FR-SCAN-8, FR-UI-1, FR-UI-2, FR-UI-4, FR-UI-5, FR-UI-6, FR-ADM-1, FR-ADM-3.
8. **D1** (High): No data classification scheme.
9. **E1** (High): The technology evaluation is almost entirely unverified (web research was blocked).
10. **H1** (High): Attack vectors identified during architecture assessment are missing from the repository threat model: agent-card or agent-to-agent discovery spoofing, multimodal (image or PDF) injection, error-message injection, evasion or denial of service aimed at the scanner and classifiers, and abuse of dynamic client registration.

## 2. Method and limits

**Checked by script** (re-runnable, Section 7): identifier resolution (done by `scripts/check_docs.py`); requirement to control and requirement to test coverage; threat to control and threat to test counts; NFR references in the test catalogue; control phase versus requirement phase; test-case phase versus requirement phase; counts of `[VERIFY]`, `TBD` and "to be set"; presence of selected terms across documents; existence of referenced paths (all referenced paths exist).

**Checked by reading**: coverage against the master brief's twenty deliverables and technical-implementation list; severity scales, role names and parameters across runbook, playbooks, spec and catalogue; whether stated terms are defined; whether threats named in the original assessment appear in the repository.

**Not checked**: truth of any product, protocol, cloud or regulatory statement (verification was blocked; see E1 to E4); whether diagrams render; whether the HTML, workflows or scripts behave on other platforms; the "Threats" column of requirement rows against the catalogue; prose quality; legal sufficiency. Each requirement-to-test mapping was derived from case headers and catalogue test lists, so a case that exercises a requirement without naming it is counted as missing.

**Severity**: Critical = would make a core guarantee false or unsafe to proceed; High = blocks or misleads the next gate, or leaves a major requirement unowned or unverifiable; Medium = real risk or rework if not closed by the stated gate; Low = tidiness or small inconsistency.

## 3. Gap register

### A. Coverage against the master brief

| ID | Severity | Gap | Evidence | Affected documents | Recommendation | Owner (role) | Close by |
|---|---|---|---|---|---|---|---|
| A1 | High | The brief's first task, a critical architecture assessment (missing attack vectors, weak assumptions, architectural gaps, reuse list, deterministic versus LLM-based controls, bottlenecks, regulatory and operational risks), is not a document in the repository. Its content is scattered across architecture principles and Section 13, threat-model Section 4, the tech evaluation and the PRD risk table. | No file in `Plan/` or `docs/` holds the assessment; its working version existed only in an assistant planning file outside the repository. | Plan/architecture.md, Plan/threat-model.md, docs/tech-evaluation.md, docs/prd.md | Write `docs/architecture-assessment.md` consolidating the assessment, linking each finding to the requirement, control or ADR that answers it. | Security architect | Phase 0 sign-off |
| A2 | High | No database schema or data model. Only a logical outline exists, so schema freeze (Phase 1) has nothing to freeze against; immutability triggers, row-level-security design, role model and audit table layout are described in prose only. | Plan/architecture.md Section 7; Plan/functional-spec.md Section 7; docs/deployment-architecture.md 6.1 | Plan/architecture.md, Plan/functional-spec.md, docs/deployment-architecture.md | Produce a data-model document with entity attributes, keys, constraints, tenancy columns, RLS policy outline, DB roles and an initial migration plan; decide ADR-4 first. | Backend lead with security architect | Before Phase 1 |
| A3 | High | No API specification. Only conventions exist (REST under /v1, problem+json, idempotency keys); no resources, operations, schemas, authorization per endpoint or error catalogue. | Plan/functional-spec.md Section 4.21; Plan/architecture.md 4.4 | Plan/functional-spec.md, Plan/architecture.md | Draft an OpenAPI outline for registry, approvals, findings, incidents and gateway-facing events; map each endpoint to FR IDs, roles and SoD rules. | Backend lead | Before Phase 1 |
| A4 | Medium | No authorization policy set and no authentication flow descriptions beyond the single call sequence. Rego policy structure, inputs, obligations and test strategy are not shown; token exchange, sender-constrained token and approval-token flows are not drawn. | Plan/architecture.md Section 6 (sequences) and 4.2; Plan/functional-spec.md FR-AUTHN-1..6, FR-AUTHZ-1..8 | Plan/architecture.md, controls/catalogue.yaml (CTL-05, CTL-06, CTL-07) | Add an authentication and authorization design note: flows (agent to gateway, gateway to server, human approval), policy input/output schema, example policies and their `opa test` cases. | Identity lead, security engineering | Before Phase 1 (basic) and Phase 2 (full) |
| A5 | Medium | Logging strategy, error handling and configuration management are not stated as one coherent design. Pieces exist (FR-AUD-*, FR-OBS-*, FR-ADM-1, problem+json, redaction) but there is no log taxonomy, level and sampling policy, correlation-ID standard, error code catalogue or config layering and validation scheme. | Plan/functional-spec.md Sections 4.14, 4.18, 4.20, 4.21 | Plan/functional-spec.md, Plan/architecture.md | Write a short cross-cutting design note covering log events versus audit events, redaction points, error model and config sources. | Backend lead | Before Phase 1 |
| A6 | Medium | The brief asks for the security implications of each architectural choice in the performance and scalability section. Targets exist; the per-choice implications (for example fail-closed versus availability, cache TTL versus drift window, inline versus asynchronous inspection) are only partly tabulated. | Plan/architecture.md Section 9; docs/deployment-architecture.md Section 8; controls/catalogue.yaml parameters | Plan/architecture.md, docs/deployment-architecture.md | Add a trade-off table (choice, benefit, security consequence, residual risk, who accepts it). | Security architect | Phase 0 sign-off |
| A7 | Medium | Dashboard deliverable is a requirements list only: no information architecture, screens, drill-down paths, relationship-graph design or accessibility plan beyond a WCAG target. | Plan/functional-spec.md Section 4.17 (FR-UI-1..7); docs/prd.md Section 7 | Plan/functional-spec.md, docs/prd.md | Add a UX outline (screens and flows for approval queue, drift diff, fleet graph) before Phase 1 UI work. | Product owner with frontend lead | Before Phase 1 |
| A8 | Low | Deliverables 10 to 13 (gateway implementation, scanning engine, policy enforcement engine, dashboard code) and the working MVP are not started. Expected for this stage but recorded so readiness statements stay honest. | `services/*/README.md` stubs; empty `policy/`, `web/`, `db/`, `deploy/`, `tests/` | Whole repository | Track through the roadmap Phase 1. | Delivery lead | Phase 1 |

### B. Traceability

| ID | Severity | Gap | Evidence | Affected documents | Recommendation | Owner (role) | Close by |
|---|---|---|---|---|---|---|---|
| B1 | High | 11 of 115 requirements are implemented by no control in the catalogue: FR-SCAN-7, FR-SCAN-8, FR-RT-1, FR-UI-1, FR-UI-2, FR-UI-3, FR-UI-4, FR-UI-5, FR-UI-6, FR-ADM-1, FR-ADM-3. A requirement with no control has no owner, evidence or failure behaviour. | Computed: requirements listed in `controls/catalogue.yaml` versus FR rows in the spec. | Plan/functional-spec.md, controls/catalogue.yaml | Assign each to an existing control or add controls (for example a dashboard/approval-workflow control for FR-UI-*, a configuration-management control for FR-ADM-1/3, a re-scan control for FR-SCAN-7, an external-LLM-privacy control for FR-SCAN-8, and add FR-RT-1 to CTL-03 or CTL-06). | Security engineering | Phase 0 sign-off |
| B2 | High | 9 requirements have no test case at all, directly or through a control: FR-SCAN-7, FR-SCAN-8, FR-UI-1, FR-UI-2, FR-UI-4, FR-UI-5, FR-UI-6, FR-ADM-1, FR-ADM-3. A further 36 are covered only through a control-level test list, not by a case that names them. | Computed: requirement references in the headers of `docs/testing/cases.md` and in the catalogue `tests` field. | Plan/functional-spec.md, docs/testing/cases.md, controls/catalogue.yaml | Add cases for the uncovered requirements (UI approval flow and SoD, config validation, notification channels, external-LLM opt-in, rescan scheduling); for control-only coverage, name the requirement in the case header or accept in a documented traceability rule. | Test lead | Before Phase 1 (P1 items), then per phase |
| B3 | High | Non-functional requirements have almost no measurement cases. By references in the catalogue: NFR-1: 2, NFR-2: 0, NFR-3: 0, NFR-4: 0, NFR-5: 0, NFR-6: 0, NFR-7: 0, NFR-8: 1, NFR-9: 2, NFR-10: 0. NFR-2 (inline classifier latency), NFR-3/4 (availability, RPO/RTO), NFR-5 (scale), NFR-6 (retention), NFR-7 (replay), NFR-10 (accessibility) have no case. | Computed: lines in `docs/testing/cases.md` that cite each NFR. | Plan/functional-spec.md Section 9, docs/testing/cases.md | Add measurement cases (load, soak, failover, retention job, decision replay, accessibility audit) with the method already described in spec Section 9. | Test lead with platform operations | Phase 2 for NFR-1/2/5, Phase 5 for NFR-3/4 |
| B4 | Medium | Several threats are tested by a single case: X2 (1), X3 (1), X4 (1), X5 (1). Gateway bypass (X2) and log injection (X5) in particular deserve more than one scenario. | Computed: test cases whose threat field names each threat. | Plan/threat-model.md Section 7, docs/testing/cases.md | Add at least one more case per thin threat (for example unmanaged stdio server discovery, notification flood on re-hash). | Test lead | Phase 2 |
| B5 | Medium | Acceptance criteria exist only for the MVP (AC-1..AC-9). Later phases rely on the "Verify" column and roadmap criteria, so there is no numbered acceptance list per phase for a gate review to tick. | Plan/functional-spec.md Section 11; docs/roadmap.md Section 6 | Plan/functional-spec.md, docs/roadmap.md | Add numbered acceptance criteria for phases 2 to 5 (continuing the AC series) or reference the roadmap criteria by ID, and map them to cases. | Product owner | Before Phase 2 |
| B6 | Medium | The MCP lifecycle requirements (twelve rows) have no IDs, so they cannot be referenced, mapped or checked by script; the catalogue refers to them as free text. | Plan/functional-spec.md Section 4.12; controls/catalogue.yaml CTL-18 | Plan/functional-spec.md, controls/catalogue.yaml, docs/testing/cases.md | Give each lifecycle row its own requirement ID (a new ID series) and map the rows to TC-P1..P4. | Specification owner | Phase 0 sign-off |

### C. Cross-document inconsistencies

| ID | Severity | Gap | Evidence | Affected documents | Recommendation | Owner (role) | Close by |
|---|---|---|---|---|---|---|---|
| C1 | High | Phase tags conflict between test cases and the requirements they exercise, and between design documents: TC-B2 (P1) uses FR-RT-2 (P2); TC-K1 (P2) uses FR-ID-5 (P4); TC-L3 (P3) uses FR-SCAN-5 (P4); TC-O1 (P2) uses FR-EXEC-1 (P4). TC-Z6 (Phase 1, MVP, mapped to AC-5) also tests detection of a full-chain rewrite against an external anchor, but anchoring (FR-AUD-4) is Phase 2. FR-SUP-1 (signing and admission, Phase 4) conflicts with the CI/CD and deployment designs that need signing in CI and admission checks by Phase 2 (DA-3). | Computed comparison of phase tags; docs/ci-cd-pipeline.md Section 10; docs/deployment-architecture.md Section 16; docs/roadmap.md F1, F2 | Plan/functional-spec.md, docs/testing/cases.md, docs/ci-cd-pipeline.md, docs/deployment-architecture.md | Resolve each conflict explicitly: retag requirement or test, or split the test; record the decision in the spec change log. | Specification owner with test lead | Phase 0 sign-off |
| C2 | Medium | Control phases do not always match the earliest requirement they implement: CTL-14 is P2/P4 but includes FR-OBS-1 (P1); CTL-18 is P2 but includes FR-DRIFT-2 (P1); CTL-21 is P3/P4 but includes FR-RT-10 (P2). | Computed comparison of `phase` in the catalogue with spec phase tags. | controls/catalogue.yaml, Plan/functional-spec.md | Align the control phase with the earliest requirement or split the control; note partial delivery per phase. | Security engineering | Phase 0 sign-off |
| C3 | Medium | Two severity scales named SEV1..SEV4 are defined with different criteria: the runbook scale is for platform operations, the playbook scale is for security incidents. Same labels, different meanings, and no rule for incidents that are both (for example a quarantine storm during an attack). | docs/runbooks/operational-runbook.md Section 3; docs/playbooks/incident-response-playbooks.md Section 3 | docs/runbooks/operational-runbook.md, docs/playbooks/incident-response-playbooks.md | Define one incident severity model with an ops/security dimension, or rename one scale; state how the higher severity wins. | Incident commander and platform operations | Before Phase 2 |
| C4 | Medium | Role vocabulary is inconsistent. The spec defines 9 roles; the catalogue assigns 14 different owner-role strings (several are compound, for example "Security operations / audit liaison"); the runbook and playbooks add on-call, incident commander, service owner, compliance liaison, communications lead and scribe. There is no mapping or RACI. | Roles in `controls/catalogue.yaml`, Plan/functional-spec.md Section 2, runbook Section 3, playbooks Section 2 | Plan/functional-spec.md, controls/catalogue.yaml, docs/runbooks/operational-runbook.md, docs/playbooks/incident-response-playbooks.md | Create one role glossary and RACI (platform roles, operational roles, governance roles) and use only those names in the catalogue. | Security architect | Phase 0 sign-off |
| C5 | Low | Deployment design extends the architecture without updating it: an `edge` namespace, node pools, Bundle server, Incident manager as separate workload, and a Compose topology appear only in `docs/deployment-architecture.md`; `Plan/architecture.md` Section 8 still shows the shorter version. | Plan/architecture.md Section 8; docs/deployment-architecture.md Sections 3 and 13 | Plan/architecture.md, docs/deployment-architecture.md | On next revision of the architecture, replace Section 8 with a summary that points to the deployment document. | Security architect | Before Phase 2 |
| C6 | Low | The PRD capability table groups the gateway protection row under Phase 2 while some of its requirements are Phase 1 (for example FR-AUTHN-1, FR-AUTHN-6, FR-RT-1). | docs/prd.md Section 6; Plan/functional-spec.md phase tags | docs/prd.md | Mark mixed-phase capabilities as P1/P2 and list the P1 subset. | Product owner | Before Phase 1 |

### D. Undefined or underspecified terms and parameters

| ID | Severity | Gap | Evidence | Affected documents | Recommendation | Owner (role) | Close by |
|---|---|---|---|---|---|---|---|
| D1 | High | No data classification scheme. Requirements depend on classes such as "confidential or above" and "tenant data tags" (FR-AUTHZ-5, FR-RT-6), the runbook and playbooks talk about regulated and confidential data, yet no document defines the classes, who assigns them, how they attach to tools, resources and data sources, or how DLP uses them. | Plan/functional-spec.md FR-AUTHZ-5, FR-RT-6; docs/playbooks/incident-response-playbooks.md PB-04 | Plan/functional-spec.md, controls/catalogue.yaml (CTL-07, CTL-10) | Define a classification model (levels, labelling source, inheritance, default) and add requirements for assignment and enforcement. | Data protection lead with security architect | Before Phase 1 (labels), Phase 2 (enforcement) |
| D2 | Medium | "Emergency policy" is used to waive the different-approver rule (FR-AUTO-5, playbooks, test case) but is not defined: who may invoke it, what it permits, how it is approved and recorded. | Plan/functional-spec.md FR-AUTO-5; docs/playbooks/incident-response-playbooks.md Section 2; docs/testing/cases.md TC-K2 | Plan/functional-spec.md, docs/playbooks/incident-response-playbooks.md, controls/catalogue.yaml (CTL-12) | Define the emergency policy (scope, approvers, expiry, audit event) or remove the exception. | Security architect | Before Phase 2 |
| D3 | Medium | Legal hold and evidence-vault access are operational facts without matching requirements: the spec has retention (NFR-6, FR-ADM-5) but no requirement for legal hold, no named role set for raw-evidence access, and no requirement for chain-of-custody records. | Plan/functional-spec.md NFR-6, FR-ADM-5; docs/runbooks/operational-runbook.md 7.8; docs/playbooks/incident-response-playbooks.md 4.3 | Plan/functional-spec.md | Add requirements for legal hold, evidence access roles and chain of custody; add test cases. | Compliance liaison | Phase 2 |
| D4 | Medium | Many numeric parameters are placeholders. The catalogue says "to be set" 22 times; CI/CD has 6, deployment 3, runbook 15 `[TBD]`. Examples: policy bundle staleness limit, approval timeout, importer limits, anchor interval, buffer capacity, rate limits, alert thresholds, vulnerability thresholds. No owner or date is attached, so enforcement cannot be implemented or tested. | `to be set`/`TBD` counts in controls/catalogue.yaml and the documents. | controls/catalogue.yaml, docs/ci-cd-pipeline.md, docs/deployment-architecture.md, docs/runbooks/operational-runbook.md | Create a parameter register (name, default, range, owner, decision date) and require every "to be set" to appear there. | Security architect | Before Phase 1 (P1 parameters), then per phase |
| D5 | Medium | The default audit retention of 13 months hot and 7 years cold has no stated basis and may conflict with data-minimisation and storage-limitation duties for personal data stored in audit excerpts. | Plan/functional-spec.md NFR-6; compliance/compliance-matrix.md Section 6 | Plan/functional-spec.md, compliance/compliance-matrix.md | Obtain legal input per jurisdiction; replace the default with a justified policy or mark it per tenant. | Compliance liaison and legal | Before Phase 2 |
| D6 | Medium | Performance targets lack a defined reference setup. NFR-1 refers to "reference hardware" and "mock upstream" without a hardware class, payload mix or concurrency profile; "10,000 concurrent sessions" and "5,000 calls/s" have no workload definition. | Plan/functional-spec.md Section 9 | Plan/functional-spec.md, docs/deployment-architecture.md | Define the reference environment and workload in a test plan before the first load test. | Test lead | Before Phase 2 |
| D7 | Low | High-impact action classes are partly configurable ("customers may add classes") and the "critical" resource tag is used without definition or governance. | Plan/functional-spec.md FR-AUTHZ-5 | Plan/functional-spec.md | Define how classes and tags are added, reviewed and audited. | Security engineering | Phase 2 |

### E. Unverified claims and placeholders

| ID | Severity | Gap | Evidence | Affected documents | Recommendation | Owner (role) | Close by |
|---|---|---|---|---|---|---|---|
| E1 | High | The technology evaluation is almost entirely unverified (web research was blocked). Product existence, licences, capabilities, versions and performance of every candidate scanner, gateway, IdP, DLP tool, classifier and supply-chain tool are background knowledge. Build-versus-extend (ADR-1) and IdP capability decisions (ADR-2) cannot be made from it. | docs/tech-evaluation.md Section 1 and verification log; `[VERIFY]` count 35 | docs/tech-evaluation.md, Plan/architecture.md | Complete the verification checklist (tech evaluation Section 8) from primary sources and run spikes S1..S6. | Security architect | Before Phase 2 |
| E2 | High | The compliance matrix has not been reviewed by legal or compliance and every framework identifier (articles, requirement numbers, control IDs, technique IDs) is unverified. OWASP MCP entries are "TBD". It must not be used as an authoritative mapping. | compliance/compliance-matrix.md Sections 1, 2, 7 | compliance/compliance-matrix.md, Plan/functional-spec.md Section 4.19 | Verify identifiers from official sources; schedule legal review (FR-COMP-5) before any external use. | Compliance liaison and legal | Phase 3 (verification can start in Phase 2) |
| E3 | Medium | MCP protocol and authorization claims (current spec revision, transports, sampling, elicitation, roots, authorization requirements, resource indicators, dynamic client registration) have not been checked against the current specification. | Plan/functional-spec.md Section 4.12 and FR-AUTHN-*; Plan/architecture.md; docs/tech-evaluation.md 3.3 | Plan/functional-spec.md, Plan/architecture.md, controls/catalogue.yaml (CTL-05, CTL-18) | Pin a specification revision, record it in the compatibility matrix, and review the spec requirements against it. | Security architect | Before Phase 1 |
| E4 | Medium | Cloud-specific claims (metadata hardening, object lock, workload identity, sandbox runtimes, managed database features, egress controls) are unverified for any cloud. | docs/deployment-architecture.md Section 12 and 17 (`[VERIFY]` 18) | docs/deployment-architecture.md, docs/ci-cd-pipeline.md | Choose the first target cloud and verify its capabilities before Phase 2 deployment work. | Platform lead | Before Phase 2 |
| E5 | Medium | Pipeline artefacts have never run: `docs-check.yml`, the Dependabot file and the product-gate template are untested; action names, versions and commit SHAs are unverified; the single workflow uses a tag under waiver W-001. | docs/ci-cd-pipeline.md Sections 7 and 11; .github/workflows/docs-check.yml | docs/ci-cd-pipeline.md, .github/ | Create the remote, run the workflow, verify and pin actions, and lint workflow files. | DevSecOps engineer | Before Phase 1 |
| E6 | Medium | Effort estimates, targets and detector budgets are proposals without data: 8 to 10 / 10 to 12 / 8 / 12 / 12+ weeks, latency, availability, 95 percent recall and 90 percent precision, alert budgets. No corpus exists to measure detector quality. | docs/roadmap.md Sections 1 and 8; Plan/functional-spec.md Sections 9 and 10 | docs/roadmap.md, Plan/functional-spec.md | Re-baseline after spikes and Phase 1; build and version the labelled corpus early. | Delivery lead | Phase 1 |
| E7 | Low | Placeholders remain by design but are numerous: CLAUDE.md VERIFY 1/TBD 2, architecture.md VERIFY 17/TBD 0, functional-spec.md VERIFY 11/TBD 0, threat-model.md VERIFY 5/TBD 0, README.md VERIFY 0/TBD 1, compliance-matrix.md VERIFY 0/TBD 15, ci-cd-pipeline.md VERIFY 9/TBD 2, deployment-architecture.md VERIFY 18/TBD 0, incident-response-playbooks.md VERIFY 7/TBD 5, roadmap.md VERIFY 3/TBD 0, operational-runbook.md VERIFY 0/TBD 15, tech-evaluation.md VERIFY 35/TBD 0, cases.md VERIFY 2/TBD 0 | Computed counts of `[VERIFY` and `TBD` per file. | Multiple | Track in the parameter register (D4) and the verification checklist (E1). | Document owners | Ongoing |

### F. Open decisions and missing inputs

| ID | Severity | Gap | Evidence | Affected documents | Recommendation | Owner (role) | Close by |
|---|---|---|---|---|---|---|---|
| F1 | High | ADR-3 (approval channel), ADR-4 (tenancy) and ADR-6 (policy language) gate Phase 1 and are open. ADR-1 (gateway), ADR-2 (IdP), ADR-5 (stdio) and ADR-7 (anchoring) gate Phase 2 and are open. | Plan/architecture.md Section 12; docs/roadmap.md Section 4 | Plan/architecture.md, docs/roadmap.md | Hold a decision session for ADR-3, 4 and 6 at Phase 0 sign-off; schedule spikes for the rest. | Security architect and product owner | Phase 0 sign-off |
| F2 | High | No named owners: the PRD owner is unassigned, control owners are roles only, risk owners are blank, there are no document reviewers, and no team, budget or cost model exists. Without owners the review, sign-off and risk acceptance steps cannot happen. | docs/prd.md header and Section 11; docs/roadmap.md Section 8; compliance/compliance-matrix.md header | All documents | Name owners and reviewers; record team assumptions; approve the budget envelope. | Sponsor | Phase 0 sign-off |
| F3 | Medium | Customer-side inputs are missing: SIEM and SOAR targets, jurisdictions and regulators in scope, pilot scope (business unit, number of agents and servers, environments), and approval channel preference. | docs/prd.md Section 12; Plan/functional-spec.md Section 12 | docs/prd.md, Plan/functional-spec.md, compliance/compliance-matrix.md | Collect and record these inputs; update the PRD and spec. | Product owner | Before Phase 1 |
| F4 | Medium | Spikes S1..S6 (about 8 weeks of work) and verification of unverified items are not scheduled in any phase duration. | docs/tech-evaluation.md Section 6; docs/roadmap.md Section 4 and F4 | docs/roadmap.md | Schedule spikes in Phase 0/1 and re-baseline Phase 2. | Delivery lead | Phase 0 sign-off |

### G. Process, tooling and assurance

| ID | Severity | Gap | Evidence | Affected documents | Recommendation | Owner (role) | Close by |
|---|---|---|---|---|---|---|---|
| G1 | High | No independent review or sign-off of any document. All are first drafts from one author-assistant pairing; none has a review date, reviewer or approval record. Findings in this register were produced by the same process that produced the documents. | Document headers (Version rows show "draft") | All documents | Run a structured review by security, architecture, compliance and operations; record outcome and date in each header and the change logs. | Sponsor and document owners | Phase 0 sign-off |
| G2 | Medium | The consistency checker has blind spots: it does not validate Mermaid syntax, Markdown links, table column counts, prose counts (for example 65 cases, 27 controls, 15 playbooks, 115 requirements), TC references outside the catalogue and the new review file, or the "Threats" column of the requirement rows against the catalogue. | scripts/check_docs.py | scripts/check_docs.py | Extend the checker (link check, count assertions, TC reference check in all documents, Mermaid parse via a CLI when available). | DevSecOps engineer | Phase 1 |
| G3 | Medium | Rendering and execution are unverified: Mermaid diagrams in five documents, the generated HTML spec (layout, dark mode, phone width), and the GitHub workflow have never been rendered or run. | CLAUDE.md; docs/ci-cd-pipeline.md; Plan/functional-spec.html | Plan/*.md, docs/*.md, Plan/functional-spec.html | Render all diagrams and the HTML in a browser and fix issues; add a CI render check. | DevSecOps engineer | Before Phase 1 |
| G4 | Medium | Repository governance controls are designed but not in place: no remote, no branch protection, no code owners, no signed commits, no environments. | docs/ci-cd-pipeline.md Section 5 | docs/ci-cd-pipeline.md | Create the remote and apply Section 5 settings; name code owners. | Engineering management | Before Phase 1 |
| G5 | Medium | The test catalogue is a specification. There is no executable harness, no formal fixture definitions beyond narrative, and no labelled corpora for poisoning and injection detection although cases A1..A5 and D1..D5 need them for precision and recall. | docs/testing/cases.md Sections 1 and 21; Plan/functional-spec.md Section 10 | docs/testing/cases.md | Define fixture and corpus specifications; make the harness a Phase 1 deliverable (roadmap F6). | Test lead | Phase 1 |
| G6 | Medium | Facts live in several documents with only partial automated protection (for example 5 s containment, 60 s cache, 10 min token lifetime, 30 days, retention defaults, replica counts, severity targets). Editing one copy can silently diverge from the others. | Parameters repeated across the spec, catalogue, runbook and deployment document | Multiple | Create the parameter register (D4) and have the checker compare registered values with their mentions. | Security architect and DevSecOps | Phase 1 |
| G7 | Low | Navigation relies on README and CLAUDE.md; there is no documentation index with reading order per audience, and only the spec has an HTML rendering. | README.md; CLAUDE.md | README.md | Add an audience-based reading guide; consider rendering the other documents. | Document owner | Phase 1 |

### H. Security substance

| ID | Severity | Gap | Evidence | Affected documents | Recommendation | Owner (role) | Close by |
|---|---|---|---|---|---|---|---|
| H1 | High | Attack vectors identified during architecture assessment are missing from the repository threat model: agent-card or agent-to-agent discovery spoofing, multimodal (image or PDF) injection, error-message injection, evasion or denial of service aimed at the scanner and classifiers, and abuse of dynamic client registration. Only the tech evaluation mentions two of them. Related abuse of resource templates exists only as a protocol-lifecycle line. | Term search across all documents (agent card, multimodal, error message, dynamic client registration, evasion): 0 hits in the threat model. | Plan/threat-model.md, controls/catalogue.yaml, docs/testing/cases.md | Add the vectors as threats (X9 onward) with controls and at least one test each; decide which are out of scope with reasons. | Security architect | Before Phase 1 (threat list), Phase 2 (controls and tests) |
| H2 | Medium | No privacy analysis of the platform itself. It stores identities, agent activity, redacted excerpts and evidence about customer users and data; there is no data inventory for the platform, no lawful-basis or minimisation analysis, and no DPIA-style assessment (the matrix treats DPIAs as the organisation's duty). | compliance/compliance-matrix.md Section 6; Plan/functional-spec.md FR-AUD-3 | Plan/functional-spec.md, compliance/compliance-matrix.md, docs/deployment-architecture.md | Write a platform data inventory and privacy assessment; feed retention (D5) and residency requirements. | Data protection lead | Before Phase 2 |
| H3 | Medium | Key management for the platform is not specified as a requirement set: policy-bundle signing key, anchor credentials, image-signing identity, tenant keys and break-glass secrets appear in the runbook, CI/CD and deployment documents, but the spec has only FR-ADM-2 (per-tenant keys, later phase) and no lifecycle, rotation, revocation or compromise requirements for these keys. | docs/runbooks/operational-runbook.md 7.5; docs/ci-cd-pipeline.md Section 6; docs/deployment-architecture.md Section 5 | Plan/functional-spec.md, controls/catalogue.yaml | Add key-management requirements and a control; add compromise playbook steps. | Security architect | Before Phase 2 |
| H4 | Medium | Approver behaviour is a primary assurance for high-impact actions yet is only monitored by a metric. There is no test or threat entry for approver fatigue, social engineering of approvers, or approval of misleading summaries, and the approval request content (what the human sees) is not specified. | controls/catalogue.yaml CTL-07 (false negatives, bypass); Plan/functional-spec.md FR-AUTHZ-5, FR-UI-3 | controls/catalogue.yaml, docs/testing/cases.md, Plan/functional-spec.md | Specify approval request content, add a threat and tests (misleading summary, bulk approval), and add step-up authentication requirements. | Security engineering and UX | Before Phase 2 |
| H5 | Low | The platform scope excludes model-internal risks, but this is not stated against specific classes such as system-prompt leakage or training-data memorisation, so readers may assume they are covered. | Plan/threat-model.md Section 4 N; compliance/compliance-matrix.md Section 6 | Plan/threat-model.md | State explicit exclusions with the reason and the compensating organisational control. | Security architect | Phase 0 sign-off |

## 4. Coverage matrices (computed)

### 4.1 Threats: controls and test cases

| Threat | Controls | Test cases |
|---|---|---|
| A | 4 (CTL-02, CTL-03, CTL-09, CTL-15) | 6 |
| B | 2 (CTL-03, CTL-15) | 5 |
| C | 4 (CTL-01, CTL-05, CTL-06, CTL-26) | 3 |
| D | 3 (CTL-07, CTL-09, CTL-15) | 5 |
| E | 5 (CTL-06, CTL-07, CTL-16, CTL-23, CTL-24) | 8 |
| F | 4 (CTL-01, CTL-04, CTL-05, CTL-20) | 2 |
| G | 3 (CTL-04, CTL-05, CTL-15) | 6 |
| H | 2 (CTL-08, CTL-11) | 5 |
| I | 5 (CTL-08, CTL-09, CTL-10, CTL-15, CTL-22) | 6 |
| J | 1 (CTL-19) | 2 |
| K | 3 (CTL-07, CTL-12, CTL-14) | 7 |
| L | 2 (CTL-17, CTL-27) | 3 |
| M | 3 (CTL-12, CTL-19, CTL-20) | 2 |
| N | 1 (CTL-21) | 2 |
| O | 1 (CTL-11) | 4 |
| P | 2 (CTL-14, CTL-18) | 6 |
| X1 | 1 (CTL-02) | 3 |
| X2 | 2 (CTL-01, CTL-26) | 1 |
| X3 | 1 (CTL-18) | 1 |
| X4 | 1 (CTL-18) | 1 |
| X5 | 1 (CTL-13) | 1 |
| X6 | 5 (CTL-02, CTL-13, CTL-16, CTL-23, CTL-25) | 3 |
| X7 | 1 (CTL-03) | 2 |
| X8 | 5 (CTL-13, CTL-15, CTL-23, CTL-24, CTL-27) | 2 |

Every threat has at least one control and one test case; thin spots are listed in B4.

### 4.2 Requirements: coverage summary

| Measure | Count |
|---|---|
| Requirements (FR rows) | 115 |
| With no control | 11 |
| With no test case (direct or through a control) | 9 |
| Covered only through a control-level test list | 36 |
| Non-functional requirements | 10 (referenced by at least one case: 3) |

### 4.3 Phase conflicts (see C1, C2)

| Item | Phase | Conflicts with | Phase |
|---|---|---|---|
| TC-B2 | P1 | FR-RT-2 | P2 |
| TC-K1 | P2 | FR-ID-5 | P4 |
| TC-L3 | P3 | FR-SCAN-5 | P4 |
| TC-O1 | P2 | FR-EXEC-1 | P4 |
| TC-Z6 | P1 (MVP) | FR-AUD-4 (anchoring) | P2 |
| FR-SUP-1 | P4 | docs/ci-cd-pipeline.md and docs/deployment-architecture.md need it in P1/P2 | P1/P2 |
| CTL-14 | P2/P4 | FR-OBS-1 | P1 |
| CTL-18 | P2 | FR-DRIFT-2 | P1 |
| CTL-21 | P3/P4 | FR-RT-10 | P2 |

## 5. Items already tracked elsewhere

These are known and recorded; this register links rather than duplicates them.

| Where | Items | Related gaps |
|---|---|---|
| `docs/roadmap.md` Section 9 | F1 TC-Z6 anchoring; F2 FR-SUP-1 timing; F3 Phase 5 requirement coverage; F4 spikes unscheduled; F5 open ADRs; F6 harness absent; F7 requirements without cases; F8 team assumptions | C1, F1, F4, B2, F2, G5 |
| `compliance/compliance-matrix.md` Section 7 | Unverified identifiers; coverage not exhaustive; review pending | E2 |
| `docs/testing/cases.md` Section 21 | Requirements without a dedicated case; detector corpora undefined | B2, G5 |
| `docs/tech-evaluation.md` Section 8 | Verification checklist | E1, E3 |
| `docs/ci-cd-pipeline.md` Section 11 | Pin and verify actions; thresholds; owners | E5, D4, G4 |
| `docs/deployment-architecture.md` Section 17 | Eleven open decisions | F1, E4 |

New in this review (not tracked elsewhere before): A1, A2, A3, A4, A5, A6, A7, B1, B3, B4, B5, B6, C2, C3, C4, C5, C6, D1 to D7, E6, F2, F3, G1, G2, G3, G6, G7, H1 to H5.

## 6. Prioritised action plan

| When | Gaps to close | Why now |
|---|---|---|
| Phase 0 sign-off | A1, A6, B1, B6, C1, C2, C4, F1, F2, F4, G1, H5 | They determine whether the design set can be approved: ownership, review, assessment, traceability and phase conflicts |
| Before Phase 1 | A2, A3, A4, A5, A7, B2, C6, D1, D4, E3, E5, F3, G3, G4, H1 | Build-level specifications and decisions the MVP needs on day one |
| Phase 1 | A8, E6, G2, G5, G6, G7 | Harness, corpus, checker and parameter register while the MVP is built |
| Before Phase 2 | B5, C3, C5, D2, D5, D6, E1, E4, H2, H3, H4 | Gateway, IdP, privacy and key-management decisions that shape runtime protection |
| Phase 2 and later | B3, B4, D3, D7, E2 | Runtime-phase tests, evidence and compliance items |
| Ongoing | E7 | Keep placeholders visible and shrinking |

Combined entries (for example "Before Phase 1 (P1 items), then per phase") are listed under their first gate.

## 7. Re-running the numeric checks

The counts in Sections 1 and 4 and in B1 to B4, C1, C2, D4 and E7 come from a one-off analysis that parses: requirement rows in `Plan/functional-spec.md` (ID, priority, phase); the `requirements`, `tests` and `threats` fields in `controls/catalogue.yaml` (via `scripts/catalogue_lib.py`); test-case headers in `docs/testing/cases.md` (threat, requirement and phase fields); and `[VERIFY`, `TBD`, "to be set" counts per file. The recommended follow-up (G2) is to fold these checks into `scripts/check_docs.py` as warnings, so the register can be refreshed mechanically. Until then, treat counts as accurate at the document versions listed above.

## 9. Closure update (v0.2)

The 14 High gaps were worked on after the register was written. Status vocabulary: **Closed, pending review** (the artefact or change exists but nobody independent has reviewed it, so it is a draft, not an approved fact); **Partly closed**; **Open** (needs people, decisions or evidence this work could not supply). Counts in the register above are the original counts; this table is the current status. `scripts/check_docs.py` passes after the changes (125 requirements, 10 non-functional requirements, 9 acceptance criteria, 90 test cases, 29 controls).

| Gap | Status | What changed | Where | What remains |
|---|---|---|---|---|
| A1 | Closed, pending review | Critical architecture assessment written and traced to requirements, controls, tests and decisions | `docs/architecture-assessment.md` | Review by security architecture, compliance and operations |
| A2 | Closed, pending review | Data model with tables, constraints, roles, retention and migration plan (illustrative SQL, not run) | `docs/data-model.md` | ADR-4 approval; run and validate on PostgreSQL; final names |
| A3 | Closed, pending review | API specification (endpoint table with roles, separation of duties, requirements and audit events; error catalogue) and an OpenAPI 3.1 outline | `docs/api-specification.md`, `docs/api/openapi.yaml` | Validate with an OpenAPI tool; add configuration, notification, break-glass, discovery and model endpoints |
| B1 | Closed, pending review | All 11 requirements now belong to a control: dashboard and notifications to new CTL-28; scan scheduling to CTL-02; external classifier opt-in to CTL-10; list filtering to CTL-03; configuration to CTL-27 | `controls/catalogue.yaml` | Owner review of the two new controls |
| B2 | Closed, pending review | Every requirement now has a test case directly or through its control; new cases TC-Z7..Z13, Z25 cover the former gaps. Requirements still covered only through control-level lists: 30 of 125 | `docs/testing/cases.md` v0.3 | Name the requirement in case headers where possible; execute the cases |
| B3 | Closed, pending review | Measurement cases exist for NFR-1, 2, 3, 4, 5, 6, 7 and 10 (TC-Z14..Z21) | `docs/testing/cases.md` | Reference environment and workload definition (gap D6); execution |
| C1 | Closed, pending approval | Phase conflicts resolved with proposed changes: TC-B2, TC-K1, TC-O1, TC-L3 headers corrected; TC-Z6 split with new TC-Z22; FR-SUP-1 retagged to Phase 2 with FR-SUP-4 for the server fleet and new TC-L4; control phases for CTL-14, 17, 18, 21 aligned. Script check finds no remaining test-case/requirement or control/requirement phase conflict | Spec v0.4, cases v0.3, catalogue v0.2, CI/CD pipeline v0.2, deployment architecture v0.2 | Owner approval of the retags (DEC-2 in `docs/governance.md`) |
| D1 | Closed, pending approval | Data classification model: FR-DATA-1..4, control CTL-29, test TC-Z25; default levels Public, Internal, Confidential, Restricted; unlabelled items treated as Confidential | Spec Section 4.22, catalogue | Approval of the level names and default (DEC-1); labelling source and owner process |
| E1 | Partly closed | Search-verified: MCP revision 2026-07-28 and its authorization changes; Cisco and Snyk scanners (Apache-2.0 per third-party sources); ContextForge, agentgateway, Docker MCP Gateway, Envoy AI Gateway existence and licences; Keycloak DPoP and token exchange; OPA graduation; Redis and Valkey licences | `docs/tech-evaluation.md` v0.2 verification log | Primary-source reading (LICENSE files, specification text), Cedar, supply-chain tools, DLP and classifier performance, Vault and OpenBao, cloud capabilities, spikes S1..S6 |
| E2 | Partly closed | OWASP MCP Top 10 entries and IDs verified from the official project; per-framework verification status recorded; confirmed identifiers for NIST CSF categories, ISO 27001 controls, DORA and EU AI Act articles (titles), PCI DSS structure, ATLAS techniques | `compliance/compliance-matrix.md` v0.3 | Official texts for every identifier, GDPR, SR 11-7, FFIEC, ISO 42001/23894, SOC 2, AI RMF; legal and compliance review (FR-COMP-5) |
| F1 | Partly closed | Proposed resolutions recorded for ADR-1..7 and for decisions DEC-1 and DEC-2; nothing is decided | Architecture Section 12, spec Section 12, `docs/governance.md` | Approval by the product owner and security architect |
| F2 | Open | Governance templates (role glossary, RACI, owner table, risk acceptance register) created; no names assigned | `docs/governance.md` | Name owners, reviewers, risk owners and sponsor |
| G1 | Open | Review and sign-off log created; no review has happened | `docs/governance.md` Section 4 | Independent reviews and recorded outcomes |
| H1 | Closed, pending review | Threats X9..X13 (agent-card spoofing, non-text injection, error-message injection, scanner and detector evasion or overload, client registration abuse) added with requirements FR-ID-8, FR-RT-12, FR-RT-13, FR-SCAN-10, FR-AUTHN-7, controls, five test cases and matrix rows | Threat model v0.3, spec v0.4, catalogue v0.2, cases v0.3, matrix v0.3 | Review; X9 depends on agent-to-agent standards that are still evolving |

**Summary of the 14 High gaps:** 9 closed pending review or approval (A1, A2, A3, B1, B2, B3, C1, D1, H1), 3 partly closed (E1, E2, F1), 2 open because they need people and decisions (F2, G1). No gap was closed by claiming a fact that has not been checked.

**New items created by the closure work and to watch**
- Ten new requirements (FR-DATA-1..4, FR-ID-8, FR-RT-12, FR-RT-13, FR-SCAN-10, FR-AUTHN-7, FR-SUP-4) are tagged "review required"; FR-SUP-1 changed meaning and phase.
- Twenty-five new test cases are specifications; the Phase 1 MVP set grew from 18 to 19.
- The new documents (assessment, data model, API specification, governance templates) and the OpenAPI outline have not been reviewed or validated with tools.
- The compliance mappings for the two new controls and five new threats come from background knowledge and are unverified.
- The proposed ADR resolutions and the classification defaults are recommendations only.
- The Medium and Low gaps in the register are untouched, except where the same change closed them incidentally (for example the role-name issue C4 is helped by the glossary in `docs/governance.md`, but the catalogue still uses the old strings).

## 10. Closure update for the Medium gaps (v0.3)

The 29 Medium gaps were worked on after the High gaps. Vocabulary as in Section 9. Verification status of the whole documentation set after this work: `scripts/check_docs.py` passes (149 requirements, 10 non-functional requirements, 24 acceptance criteria, 99 test cases, 30 controls) with new checks for relative links, table shapes, Mermaid structure, test-case references, stated counts, the parameter register, the seed corpus and HTML well-formedness; `scripts/validate_yaml.py` run in a throwaway virtual environment parsed all five YAML files, confirmed the stdlib catalogue loader agrees with PyYAML, and validated the OpenAPI outline (this found and fixed a real syntax error in the CI template). Counts by status are at the end.

| Gap | Status | What changed | Where | What remains |
|---|---|---|---|---|
| A4 | Closed, pending review | Authentication and authorization flows, policy structure, decision contract, illustrative Rego, unit-test design, failure behaviour | `docs/authn-authz-design.md` | Run the policy through OPA (not installed here); IdP capability (spike S2) |
| A5 | Closed, pending review | One design for audit versus operational logs, redaction, error catalogue and configuration layering | `docs/cross-cutting-design.md` | Library choices; audit event schema fields |
| A6 | Closed, pending review | Table of 13 architectural choices with benefit, security consequence, residual risk and acceptor | `docs/architecture-assessment.md` Section 7.1 | Review by acceptors |
| A7 | Closed, pending review | Dashboard information architecture, key flows, principles and states | `docs/ux-outline.md` | Visual design, prototype and usability tests are not done |
| B4 | Closed, pending review | Second test cases for X2, X3, X4, X5 (TC-Z26..Z29); X14 has two cases. X9..X13 still have one case each | `docs/testing/cases.md` v0.4 | Second cases for X9..X13 at their phase gates |
| B5 | Closed, pending review | Acceptance criteria AC-10..AC-24 for phases 2 to 5 with linked cases | Spec v0.5 Section 11 | Review; thresholds depend on the parameter register |
| B6 | Closed | The twelve lifecycle rows have IDs FR-MCP-1..12 and are referenced by the catalogue and traceability | Spec v0.5 Section 4.12 | None |
| C2 | Closed | Control phases aligned with requirement phases (done with C1); script comparison finds no conflict | Catalogue v0.3 | None |
| C3 | Closed, pending approval | One incident severity model with operational and security dimensions (higher wins); runbook refers to it | Playbooks v0.2 Section 3, runbook v0.3 Section 3 | Approval (DEC-3); response targets still proposals |
| C4 | Closed, pending approval | Catalogue owner roles reduced to the glossary roles; glossary and RACI in the governance document | Catalogue v0.3, `docs/governance.md` | Approval (DEC-6) |
| D2 | Closed, pending review | Emergency policy defined and limited to relaxing the different-approver rule (FR-AUTO-6), with glossary entry and test extension | Spec v0.5, TC-K2 | Approval (DEC-4) |
| D3 | Closed, pending review | Legal hold (FR-ADM-7), raw-evidence access and chain of custody (FR-ADM-8), tests TC-Z19 and TC-Z30 | Spec v0.5, cases v0.4 | Legal input on hold process |
| D4 | Closed, pending owner acceptance | Parameter register: 11 fixed parameters checked by script and 25 open parameters with proposed owner role and decision gate | `docs/parameter-register.md` | Owners must accept and decide the values |
| D5 | Partly closed | Retention default flagged as a placeholder pending legal input; privacy assessment lists the questions | Spec NFR-6, `docs/privacy-assessment.md` | Legal decision per jurisdiction (DEC-9) |
| D6 | Closed, pending approval | Proposed reference environment, workload model, procedures and pass criteria for the performance cases | `docs/testing/performance-test-plan.md` | Approval (DEC-7); error and memory bounds not set; nothing measured |
| E3 | Partly closed | Revision 2026-07-28 pinned; authorization, transport, sampling, elicitation and roots pages read; compatibility matrix and spec updates (sampling and roots deprecated, no protocol sessions, Origin validation) | `docs/mcp-compatibility.md`, spec Section 4.12 | Tools, resources, prompts, lifecycle, client ID metadata document and DCR pages not read; older revisions not compared |
| E4 | Partly closed | AWS adapter: six capabilities verified from documentation chunks, with design consequences (strict network policy mode, IMDS hop-limit tension, Object Lock compliance mode, Pod Identity, Multi-AZ) recorded in the deployment document | `docs/cloud-adapter-verification.md`, deployment v0.3 | Azure and Google Cloud; AWS items listed as not verified; cloud choice (CI-6) |
| E5 | Partly closed | Workflow, Dependabot and template YAML validated; template syntax error fixed; `actions/checkout` pinned to the commit of release v7.0.1 read from the GitHub API (waiver W-001 retired); CODEOWNERS example added | `.github/`, `docs/ci-cd-pipeline.md` v0.3 | Never run on GitHub; checkout SHA to be re-verified; other actions unpinned and unverified |
| E6 | Partly closed | Seed corpus (24 descriptions, 16 responses) and corpus specification; estimates unchanged | `tests/fixtures/corpus/`, `docs/testing/fixtures-and-corpora.md` | Corpus too small for any recall or precision claim; estimates and targets remain unmeasured |
| F3 | Open | Customer intake form with 15 questions, needed-by gates and blank answer columns | `docs/customer-inputs.md` | A customer must answer |
| F4 | Closed, pending approval | Spike schedule (S1..S6 plus verification) with windows, owners, dependencies and exit evidence | `docs/roadmap.md` Section 4.1 | Approval (DEC-8); needs two engineers and customer answers CI-5, CI-6, CI-8 |
| G2 | Closed | Checker extended: relative links, table column counts, Mermaid structure, test-case references everywhere, stated counts, phase-total sentence, parameter register patterns, corpus files, HTML well-formedness; negative-tested on a copy | `scripts/check_docs.py` | The "Threats" column of requirement rows is still not cross-checked against the catalogue |
| G3 | Partly closed | Mermaid structure and HTML tag balance are checked automatically | `scripts/check_docs.py` | Diagrams and HTML have still not been rendered in a browser; workflow never run |
| G4 | Open | Branch-protection and code-owner settings are specified (CI/CD Section 5) and a CODEOWNERS example exists | `.github/CODEOWNERS.example` | Needs a remote repository, real teams and settings applied |
| G5 | Closed, pending review | Fixture server specification, harness requirements, corpus format, labelling rules, splits and metrics, seed corpus | `docs/testing/fixtures-and-corpora.md`, `tests/fixtures/corpus/` | Fixtures and harness are not built; corpus growth |
| G6 | Closed | Parameter register with machine-checked fixed values | `docs/parameter-register.md`, checker | Only 11 parameters are protected; extend as values are decided |
| H2 | Partly closed | Platform data inventory, ten privacy risks with mitigations, questions for legal | `docs/privacy-assessment.md` | Legal and privacy review; decisions on retention and erasure; no formal impact assessment |
| H3 | Closed, pending review | Key management requirements FR-KEY-1..6, control CTL-30, tests TC-Z31 and TC-Z32, playbook and runbook links | Spec Section 4.23, catalogue v0.3 | Approval (DEC-5); per-cloud KMS verification |
| H4 | Closed, pending review | Approval content, step-up authentication and fatigue limits (FR-AUTHZ-9..11), threat X14, tests TC-X14 and TC-Z33, UX flow | Spec v0.5, threat model v0.4, UX outline | Detailed approval view design; IdP step-up mechanics |

**Summary of the 29 Medium gaps:** 20 closed, pending review, approval or owner acceptance (A4, A5, A6, A7, B4, B5, B6, C2, C3, C4, D2, D3, D4, D6, F4, G2, G5, G6, H3, H4; C2, B6, G2 and G6 are closed outright because they are mechanical and checked), 7 partly closed (D5, E3, E4, E5, E6, G3, H2), 2 open (F3, G4). Nothing in this table claims a fact that has not been checked; "closed, pending review" means a draft artefact exists, not that it has been approved.

**New items created by this work**
- Twenty-four new requirements since the High closure (FR-MCP-1..12 gained IDs; FR-AUTO-6, FR-ADM-7, FR-ADM-8, FR-AUTHZ-9..11, FR-KEY-1..6 are new) and nine new test cases (99 total); all are specifications.
- New documents are unreviewed; the OpenAPI outline is validated only for syntax and structure.
- Several statements about the MCP specification and AWS come from page-fetching and documentation search results rather than primary files; the documents say which.
- Proposals awaiting approval are recorded as DEC-1..DEC-9 in `docs/governance.md`.

## 11. Closure update for the Low gaps (v0.4)

Vocabulary as in Section 9. After this update `scripts/check_docs.py` passes (150 requirements, 10 non-functional requirements, 24 acceptance criteria, 100 test cases, 30 controls) and prints a placeholder inventory (counts of unverified-claim and TBD markers) on every run.

| Gap | Status | What changed | Where | What remains |
|---|---|---|---|---|
| A8 | Open (by nature) | Nothing to close in documents: the gateway, scanner, policy engine and dashboard code do not exist. Tracked as Phase 1 of the roadmap | `docs/roadmap.md` | Implementation |
| C5 | Closed | Architecture Section 8 now shows the edge namespace, policy bundle server and node pools, and states that the deployment document governs where they differ | `Plan/architecture.md` v0.5 | None |
| C6 | Closed | PRD capability row for gateway protection is marked P1/P2 with the Phase 1 subset listed | `docs/prd.md` v0.4 | None |
| D7 | Closed, pending review | Governance of extra high-impact classes and the critical resource tag defined (FR-AUTHZ-12); glossary entry; test TC-Z34; proposal DEC-10 | Spec v0.6, cases v0.5, catalogue v0.4, governance v0.3 | Approval of DEC-10 |
| E7 | Closed | Open placeholders are tracked in the parameter register (values) and the verification checklist (claims); the checker prints a placeholder inventory every run so growth is visible | `docs/parameter-register.md`, `scripts/check_docs.py` | The placeholders themselves stay until resolved |
| G7 | Closed | Audience-based reading guide and document map; the checker fails if a design document is missing from the map | `docs/index.md` | Rendering the other documents to HTML is not done (the converter supports only the subset used by the specification) |
| H5 | Closed, pending review | Explicit exclusions with reasons, residual platform help and the organisational control needed: system-prompt leakage, memorisation, adversarial inputs, hallucination, bias, server code vulnerabilities, IdP or secrets-manager compromise; shared-responsibility row in the compliance matrix | `Plan/threat-model.md` v0.5 Section 4.1, `compliance/compliance-matrix.md` v0.5 | Review |

**Summary of the 7 Low gaps:** 6 closed (C5, C6, E7, G7 outright; D7 and H5 pending review), 1 open (A8, implementation work). A helper, `scripts/sync_versions.py`, now rewrites version citations after a document is bumped.

## 8. Change history

| Version | Date | Change |
|---|---|---|
| 0.4 | 2026-11-22 | Closure update for the Low gaps (Section 11) |
| 0.3 | 2026-11-22 | Closure update for the Medium gaps (Section 10) |
| 0.2 | 2026-11-22 | Closure update for the High gaps (Section 9) |
| 0.1 | 2026-11-22 | First review of the full documentation set |

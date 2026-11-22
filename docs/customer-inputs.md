# Customer Inputs and Decisions Needed

| | |
|---|---|
| Version | 0.2 (intake form plus clearly labelled working assumptions; advances gap F3 in `docs/reviewgap.md`) |
| Depends on | `docs/prd.md` v0.4 (Section 12 open questions), `Plan/functional-spec.md` v0.7 (Section 12), `Plan/architecture.md` v0.5 (Section 12), `docs/roadmap.md` v0.4 (gates), `docs/governance.md` v0.5 |
| Status | **Blank intake form.** The gap stays open until a customer representative answers; no answer in the Answer column is real. Section 3 lists engineering working assumptions, which are NOT customer answers. Fill in with date and respondent. |

## 1. How to use

Send this form to the sponsoring customer. Each question says what it affects and when it is needed. Answers feed the PRD, specification Section 12, the compliance matrix and the roadmap; record them in `docs/governance.md` as decisions.

## 2. Questions

| ID | Question | Why it matters | Needed by | Answer | Respondent and date |
|---|---|---|---|---|---|
| CI-1 | Which SIEM (and SOAR) products must be supported at launch? | Event export format, connector scope (FR-AUD-5, FR-IR-*) | Before Phase 2 | | |
| CI-2 | Which approval channel do approvers use: the dashboard only, or ticketing or chat integration? | ADR-3; approval flows and step-up authentication | Before Phase 1 UI freeze | | |
| CI-3 | Single-tenant per deployment, or shared multi-tenant first? Any tenant needing dedicated databases or clusters? | ADR-4; schema, isolation, keys | Before Phase 1 schema freeze | | |
| CI-4 | Which jurisdictions and regulators apply (EU, UK, US, others)? Which sector rules (banking, payments, health)? | Scope of the compliance matrix, retention, residency | Before Phase 3, ideally Phase 1 | | |
| CI-5 | Which identity provider is in production and does it support sender-constrained tokens and token exchange? | ADR-2; FR-AUTHN-2, FR-AUTHN-3 | Before Phase 2 (spike S2) | | |
| CI-6 | Which cloud(s) and regions for the first deployment? Data residency constraints? | Cloud adapter verification, deployment design | Before Phase 2 | | |
| CI-7 | Pilot scope: business unit, number of agents and MCP servers, environments, data classes involved | Phase 1 acceptance and rollout | Before Phase 1 exit | | |
| CI-8 | Existing MCP gateway, API gateway or AI gateway products already in use? | ADR-1 build or extend | Before Phase 2 (spike S1) | | |
| CI-9 | Data classification scheme in use (names, levels, labelling tools)? | FR-DATA-1..4 alignment | Before Phase 1 | | |
| CI-10 | Incident response: on-call model, severity scale, regulatory reporting contacts | Runbook, playbooks, severity model | Before Phase 2 | | |
| CI-11 | Retention periods required for security logs and evidence; legal hold process | NFR-6, FR-ADM-7 | Before Phase 2 | | |
| CI-12 | Preferred secrets manager, KMS and registry for images | Key management, CI/CD | Before Phase 2 | | |
| CI-13 | Who will own the platform: named sponsor, product owner, security architect, reviewers | Governance (gaps F2, G1) | Phase 0 sign-off | | |
| CI-14 | Expected agent volume and call rates; peak periods | Capacity and load test workload | Before Phase 2 | | |
| CI-15 | Any stdio or desktop-embedded MCP use that must be covered? | ADR-5, discovery scope | Before Phase 2 | | |

## 3. Working assumptions until the customer answers

Used only so design and Phase 0 work can proceed. A real answer replaces the assumption; if the answer differs, the listed document must be revisited. None of these has been confirmed by anyone.

| ID | Working assumption | Documents affected if wrong |
|---|---|---|
| CI-1 | Export is generic structured events over syslog or HTTPS (CEF or JSON); no product-specific connector at launch | Spec FR-AUD-5, FR-IR-*, runbook |
| CI-2 | Dashboard approvals only; chat or ticketing integration after launch | ADR-3, UX outline, spec FR-AUTHZ-9..11 |
| CI-3 | Shared multi-tenant with row-level security first; a dedicated-database option designed but not built | ADR-4, data model, deployment Section 11 |
| CI-4 | Jurisdictions unknown; the compliance matrix keeps all frameworks as candidates and nothing is claimed as mandatory | Compliance matrix, privacy assessment |
| CI-5 | An OpenID Connect provider is available; sender-constrained tokens and token exchange may not be; Keycloak used for development | ADR-2, authn-authz design, spike S2 |
| CI-6 | Kubernetes on one major cloud; AWS used as the first verified example only because its documentation was readable first | Cloud adapter verification, deployment |
| CI-7 | Pilot: one business unit, under 20 agents, under 10 MCP servers, non-production data only | Roadmap Phase 1 exit, PRD |
| CI-8 | No existing MCP-aware gateway; an API gateway may exist and can sit in front | ADR-1, spike S1 |
| CI-9 | Four levels (public, internal, confidential, restricted) used as placeholders in the data design | Spec FR-DATA-*, FR-AUTHZ-5 |
| CI-10 | Standard four-level severity; business-hours on-call until Phase 2 | Runbook, playbooks |
| CI-11 | 13 months hot and 7 years cold remain placeholders (NFR-6) | NFR-6, privacy assessment |
| CI-12 | Cloud-native secrets manager and KMS of the chosen cloud; any OCI registry | Deployment Section 5, CI/CD |
| CI-13 | No named owners; roles stay generic as in the governance document | Governance |
| CI-14 | Load-test workload from the performance plan proposal (not customer data) | Performance test plan |
| CI-15 | Stdio and desktop MCP use exists and is covered by discovery and a stdio wrapper in Phase 2 | ADR-5, spec discovery requirements |

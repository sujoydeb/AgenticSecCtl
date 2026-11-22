# Enterprise Implementation Roadmap: AgenticSecCtl

| | |
|---|---|
| Version | 0.4 (planning draft; estimates are not validated by engineering) |
| Depends on | `docs/prd.md` v0.4 (Section 8 release plan), `Plan/functional-spec.md` v0.8 (phase tags on every requirement), `Plan/architecture.md` v0.6 (ADRs, Section 12), `controls/catalogue.md` v0.6 (control phases), `docs/testing/cases.md` v0.5 (phase of each test case, MVP set), `docs/deployment-architecture.md` v0.4, `docs/ci-cd-pipeline.md` v0.7, `docs/tech-evaluation.md` v0.3 (spikes S1..S6) |
| Purpose | Turn the five phases into a plan with deliverables, dependencies, effort, acceptance criteria, risks and go/no-go gates, with requirements, controls and tests allocated to phases. |
| Honesty note | Durations come from the original design plan and assume 2 to 3 engineers. Nothing has been estimated bottom-up and no team exists yet. Treat all numbers as planning ranges to be re-baselined after Phase 0 spikes and again after Phase 1. |

## 1. Assumptions and reading guide

- **Effort unit:** elapsed weeks for a core team of 2 to 3 engineers, plus part-time security architecture and compliance input. Person-week totals are not given because the team is not defined.
- **Phase tags** on requirements (P1..P5), controls and test cases are the ones in the spec, catalogue and test catalogue; this document does not change them. Where tags conflict across documents, Section 9 lists the conflict instead of silently choosing.
- **Open decisions (ADR-1..7)** gate phases (Section 4). A phase starts only when its gating decisions are made or explicitly deferred with an owner.
- Identifiers refer to the spec (`FR-*`, `NFR-*`, `AC-*`), the catalogue (`CTL-*`), the test catalogue (`TC-*`) and the spikes in the technology evaluation (`S1..S6`).
- "Acceptance" means evidence that a reviewer can check, not a statement that the capability exists.

## 2. Overview

| Phase | Theme | Est. duration | Starts when | Requirements by phase tag (M = must) | Controls (first phase) | Test cases by phase |
|---|---|---|---|---|---|---|
| 0 | Design completion | 3 to 4 weeks (largely done, not signed off) | Now | n/a | n/a | n/a |
| 1 | MVP | 8 to 10 weeks | Phase 0 sign-off; ADR-3, ADR-4, ADR-6 decided | 42 FRs, all M | CTL-01..06, 08, 13, 14, 16, 18, 23, 24, 27, 28, 29 (16) | 26 (19 are MVP-gating) |
| 2 | Runtime protection | 10 to 12 weeks | Phase 1 exit; ADR-1, ADR-2, ADR-5, ADR-7 decided; spikes S1..S4 done | 70 FRs (48 M), including FR-MCP-1..3, 5..12 | CTL-07, 09..12, 15, 17, 21, 22, 26, 30 (11) | 58 |
| 3 | Enterprise governance | about 8 weeks | Phase 2 exit; legal/compliance reviewers named; framework IDs verified | 18 FRs (4 M) | CTL-25 (1) | 5 |
| 4 | Advanced threat protection | about 12 weeks | Phase 3 exit | 18 FRs (1 M) | CTL-19, 20 (2) | 8 |
| 5 | Enterprise production | 12+ weeks, open-ended | Phase 4 exit (parts can start earlier, see 3) | 2 FRs (FR-ADM-4, FR-KEY-6) plus NFR-3..5, 8 | Completion of CTL-22, 24 | 3 |

Totals: Phases 1 to 5 add up to roughly 50 to 54 weeks if run strictly in sequence, before Phase 5's open-ended items and before the Phase 0 spikes. Overlap (Section 3) can shorten the elapsed time at the cost of a larger team.

Cumulative view, sequential (weeks counted from Phase 1 start; ranges follow the duration ranges):

| Phase | Start week | End week |
|---|---|---|
| 1 | 0 | 8 to 10 |
| 2 | 8 to 10 | 18 to 22 |
| 3 | 18 to 22 | 26 to 30 |
| 4 | 26 to 30 | 38 to 42 |
| 5 | 38 to 42 | 50 to 54+ |

## 3. Workstreams and allowed overlap

| Workstream | Phases | Notes |
|---|---|---|
| Platform core (common library, registry API, schema, config, telemetry) | 1, then ongoing | Schema freeze depends on ADR-4 (tenancy) |
| Security engines (scanner, drift, gateway pipeline, injection and DLP engines, argument guards) | 1 to 4 | Largest and riskiest; owns detector quality budgets |
| Identity and authorization (IdP integration, broker, OPA policies, JIT/approvals) | 1 to 2, then 4 for delegation | ADR-2 gates sender-constrained tokens |
| Audit, evidence and incident management | 1 to 4 | Hash chain in P1; anchoring, vault and export in P2 |
| Dashboard and UX | 1 to 3 | MVP is deliberately small; fleet and graph views in P3 |
| Compliance and governance | 2 start for verification, main work in 3 | Can overlap with P2 because it is mostly documentation and verification, not runtime code |
| DevSecOps and deployment | 1 to 5 | CI gates from P1; Kubernetes manifests, admission and environments from P2; multi-cloud in P5 |
| Testing and red team | 1 to 5 | Fixtures and e2e harness in P1; adversarial rounds each phase gate |

Overlaps that are safe in principle: compliance verification during Phase 2; deployment manifests and environments during late Phase 1 to Phase 2; supply-chain tooling (CI) early, even though enforcement requirements are tagged later (see finding F2). Overlaps that are not recommended: starting Phase 2 gateway work before ADR-1 and the schema freeze; starting Phase 4 items that depend on Phase 2 detectors before they are measured.

## 4. Decision gates and spikes

| Gate | Needed before | Decision or evidence | Linked docs |
|---|---|---|---|
| ADR-4 tenancy model | Phase 1 schema freeze | Single or shared multi-tenant, key hierarchy | Deployment architecture Section 9 |
| ADR-3 approval channel | Phase 1 UI freeze | Dashboard only or integration with a ticketing/chat system | Spec Section 12 |
| ADR-6 policy language | Phase 1 policies | Rego (default) or Cedar | Tech evaluation 3.4 |
| S5 scanner baselines | Phase 1 scanner design | Compare external scanners with own rules on a labelled corpus | Tech evaluation Section 6 |
| ADR-1 gateway build vs extend, spike S1 | Phase 2 start | Seven-test comparison of custom, MCP gateway, Envoy-based | Tech evaluation 3.2 |
| ADR-2 IdP and token capabilities, spike S2 | Phase 2 start | DPoP/mTLS binding, token exchange, resource indicators | Tech evaluation 3.5 |
| S3 policy latency | Phase 2 design | OPA decision latency with realistic data | NFR-1 |
| S4 detectors | Phase 2 design | Presidio-style DLP and one classifier on a labelled corpus in shadow mode | Spec Section 10 |
| ADR-5 stdio handling | Phase 2 | Wrapper, sidecar or unsupported | Architecture Section 12 |
| ADR-7 audit anchoring target | Phase 2 | Object-lock store or external timestamping; cross-account design | Deployment architecture 6.2 |
| S6 supply-chain pipeline | Phase 2 | Working SBOM, scan, signing, admission gate in a sample pipeline | CI/CD pipeline |
| Verification of `[VERIFY]` items | Before commitments on any named product | Primary-source check per checklist | Tech evaluation Section 8 |
| Legal/compliance review of mappings | Phase 3 exit | Reviewed matrix, FR-COMP-5 | Compliance matrix |

The spikes S1..S6 total about 8 weeks of effort if run one after another (2+1+1+2+1+1); they can run in parallel with late Phase 0 and early Phase 1 work but are not included in the phase durations above.

### 4.1 Proposed spike schedule (closes gap F4 once approved)

Weeks are counted backwards from the start of Phase 1 (week 0), so the spikes finish before Phase 2 design depends on them. The plan assumes two engineers; running everything sequentially by one person would take about eight weeks. Owners are roles.

| Spike | Window | Owner role | Depends on | Exit evidence | Feeds |
|---|---|---|---|---|---|
| S5 scanner baselines | week -6 to -5 | Security engineer | Seed corpus (`tests/fixtures/corpus`), external scanner access | Detection overlap table, false positives, data-egress notes | Scanner design (Phase 1) |
| S2 identity capabilities | week -6 to -5 | Security engineer (identity) | Candidate IdPs, MCP compatibility matrix | Capability matrix (PKCE S256, `iss`, resource indicators, DPoP or mTLS binding, token exchange) | ADR-2, FR-AUTHN-2/3 mode statement |
| S3 policy latency | week -5 to -4 | Backend engineer | Draft policy and data sizes (`docs/authn-authz-design.md`) | Decision latency numbers against NFR-1, cache design | ADR-6, gateway design |
| S1 gateway options | week -5 to -3 | Backend engineer and platform operator | Seven tests in tech evaluation 3.2 | Test results and latency numbers for custom, ContextForge or agentgateway, and Envoy-based setups | ADR-1 |
| S4 detectors | week -3 to -2 | Security engineer | Corpus growth, Presidio-style recognisers, one classifier | Precision, recall, latency, licence notes | Phase 2 detector plan |
| S6 supply-chain pipeline | week -2 to -1 | DevSecOps engineer | Remote repository, verified action pins | Working SBOM, scan, signing, admission gate in a sample pipeline | CI/CD stages 2 to 4, FR-SUP-1 |
| Verification of `[VERIFY]` items | weeks -6 to -1, in parallel | Security architect | Primary sources | Updated verification log | ADR decisions, compliance matrix |
| Re-baseline checkpoint | week -1 | Delivery lead | All spikes | Updated estimates for Phase 2 and the risks list | Phase 2 start gate |

Dependencies outside the team: customer answers CI-5 (IdP), CI-6 (cloud) and CI-8 (existing gateways) in `docs/customer-inputs.md`; a remote repository for S6; legal input for retention (parameter register). If a spike is skipped, the corresponding ADR stays open and Phase 2 start moves.

## 5. Phase 0: design completion (in progress)

Done (drafts, unreviewed): functional specification v0.5 and HTML, architecture v0.4, threat model v0.4, test catalogue (100 cases), technology evaluation (partly verified), architecture assessment, data model, API specification, authentication and authorization design, cross-cutting design, UX outline, MCP compatibility matrix, parameter register, performance test plan, fixtures and corpora specification, privacy assessment, cloud adapter verification (AWS), customer inputs form, governance templates, review gap register, PRD, operational runbook, incident playbooks, compliance matrix, control catalogue, CI/CD pipeline design, deployment architecture, this roadmap; a repository scaffold, consistency checker and generators.

Remaining exit criteria (itemised with owners, evidence and due weeks in `docs/governance.md` Section 8):
1. Review by security, architecture and compliance owners, with named owners and dates.
2. ADR-3, ADR-4 and ADR-6 decided; ADR-1, ADR-2, ADR-5, ADR-7 scheduled with owners.
3. Verification of `[VERIFY]` items in priority order (tech evaluation Section 8) and of framework identifiers (compliance matrix Section 7).
4. Team confirmed and estimates re-baselined (Section 8).
5. Resolution of cross-document findings in Section 9.
6. Spikes S5 scheduled before scanner design; S1..S4, S6 scheduled before Phase 2.

## 6. Phases in detail

### 6.1 Phase 1: MVP (8 to 10 weeks)

The build-level work breakdown, schedule and test mapping for this phase are in `Plan/implementation-plan.md`.

**Goal.** A working, tested core that proves the central controls: inventory, scanning, pinning and drift quarantine, deny-by-default authorization, SSRF protection and a tamper-evident audit trail, with a small dashboard.

**Deliverables**
- Repository and engineering baseline: service packages, configuration, telemetry, local Compose environment with benign and hostile MCP fixtures (`tests/fixtures`), CI gates G1.1..G1.10 for the code that exists (CI/CD pipeline).
- Common library: canonical JSON and SHA-256 hashing (RFC 8785), audit hash chain and verifier, config loading, redaction utilities (CTL-03, CTL-13).
- Registry API and database schema with migrations, row-level security per ADR-4, immutable `tool_versions`, approvals with separation of duties (FR-INV-1..4, FR-ID-1..2, SoD-1..3).
- Scanner v1: hardened importer, normaliser, deterministic rules, scoring, pluggable advisory classifier stub (FR-SCAN-1..4, 6), labelled corpus v1 and baseline precision/recall.
- Drift detection and quarantine with `tools/list` filtering in a thin gateway (FR-DRIFT-1..5, FR-RT-1, FR-AUTHN-1, FR-AUTHZ-1..3, 8).
- OPA policies and tests, deny-by-default, fail-closed (FR-POL-1..2).
- SSRF guard library used by registration, import and scanner (FR-SSRF-1..5).
- Audit chain with verification endpoint/CLI (FR-AUD-1, 2, 6), log redaction (FR-AUTHN-6, FR-OBS-1).
- Dashboard: counters, drill-down, approval queue, OIDC login with RBAC (FR-UI-1..3, 7).
- End-to-end test harness and the 19 MVP test cases.
- Data classification labels on registry items with the Confidential default (FR-DATA-1..2).

**Dependencies.** Phase 0 exit; ADR-3, ADR-4, ADR-6; Keycloak (or equivalent) for development; S5 results for scanner design.

**Indicative milestones** (weeks from phase start): 2 skeleton, CI, schema, hashing; 4 registry, approvals, scanner on corpus; 6 drift quarantine, gateway list filtering, OPA decisions; 8 audit chain, SSRF guard, dashboard; 10 acceptance run, hardening, documentation.

**Acceptance criteria**
- AC-1..AC-9 pass (spec Section 11) with the mapped cases.
- The 19 MVP test cases pass (and the Phase 1 acceptance criteria AC-1..AC-9): TC-A1, A2, A3, B1, B2, C1, C3, E1, E4, F1, G5, H1, H2, H3, H4, Z2, Z5, Z6, Z7. The other seven Phase 1 cases (TC-A4, A5, B3, F2, G2, Z10, Z20) pass or have recorded exceptions.
- Scanner detection on the benchmark corpus is measured and reported against the 95% recall / 90% precision targets, even if not yet met.
- CI gates run clean on the repository (no secret findings; dependencies scanned).
- No Critical or High finding open from the team's own SAST/dependency checks without a recorded waiver.
- Operational runbook items that Phase 1 relies on (fail-closed behaviour, restore of the database with chain verification) are exercised once in a test environment.

**Risks and mitigations**
- Rule false positives or low recall: build the labelled corpus early; shadow review of findings; keep classifier advisory.
- Tenancy decision delayed: do not freeze schema until ADR-4; keep tenant ID on every table regardless.
- Scope creep into runtime inspection: Phase 1 gateway only filters lists and allows or denies pinned tools.
- Fixture and harness effort underestimated: treat the e2e harness as a first-class deliverable.
- Discovery gap hides unmanaged servers: accepted for MVP; reported in Phase 2/3 (CTL-26).

**Not in Phase 1.** Response inspection, DLP, JIT and call-time approvals, limits and kill switch, Redis/Kafka, discovery, evidence vault, compliance engine, Kubernetes production deployment.

### 6.2 Phase 2: runtime protection (10 to 12 weeks)

**Goal.** The gateway enforces the full interceptor pipeline on real traffic with measured latency, and the platform can be deployed on Kubernetes with the network and identity controls from the deployment architecture.

**Deliverables**
- Full pipeline (architecture Section 5): authentication hardening, server identity validation, argument guards, limits and loops, response inspection with untrusted labelling and taint rule, DLP, approval gate (FR-AUTHN-2..5, 7, FR-DRIFT-7, FR-RT-2..13, FR-DATA-3..4, FR-SCAN-10, FR-SUP-1, FR-AUTO-1..5).
- JIT grants and bound approvals; break-glass (FR-AUTHZ-4..5, FR-ADM-6, FR-ID-3, FR-ID-7).
- MCP lifecycle controls: version allowlist, sampling and elicitation default-deny, roots, notifications, resources, prompts (spec Section 4.12; CTL-18).
- Egress proxy and network policy; Kubernetes environments, admission baseline, sandbox pool design (deployment architecture); CI stages 2 to 4 (build, SBOM, scan, sign, promote).
- Audit: external anchoring, evidence vault, SIEM export, log-injection escaping (FR-AUD-3..5, 7); Redis and Kafka as needed.
- Incident basics: incident records, one-action quarantine and revoke, evidence snapshot (FR-IR-1..3); monitoring thresholds and SLO dashboards (FR-BEH-1, FR-OBS-2, FR-UI-4).
- Key management, legal hold, evidence access and approval content (FR-KEY-1..5, FR-ADM-7..8, FR-AUTHZ-9..11, FR-AUTO-6).
- Multi-tenancy isolation and retention controls (FR-ADM-2, 3, 5, FR-RT-8); basic discovery (FR-INV-5); external LLM opt-in (FR-SCAN-8).

**Dependencies.** Phase 1 exit; ADR-1, ADR-2, ADR-5, ADR-7 decided from spikes S1..S4, S6; detector corpora available for shadow mode.

**Acceptance criteria**
- All 58 Phase 2 test cases pass, in addition to the Phase 1 set (no regression), and acceptance criteria AC-10..AC-17 are met.
- NFR-1/2 met in the load test on the reference setup (p95 at most 25 ms, p99 at most 60 ms on the deterministic path at 1,000 requests per second per instance; inline classifier at most 150 ms p95 or asynchronous); results published with method.
- Deployment criteria DA-1..DA-9 pass in staging (DA-5 pending a dedicated test case).
- Shadow-mode false-block rate at most 0.5% of benign calls for the injection and DLP detectors before enforcement is enabled.
- Red-team round 1 on the injection, exfiltration and token-abuse scenarios: zero unapproved high-impact actions executed.
- Containment actions take effect within 5 seconds in a timed test (FR-IR-2, FR-AUTO-4).

**Risks and mitigations**
- Gateway performance or streaming inspection misses NFR-1: S1/S3 results first; fall back to a different gateway base or a compiled-language data plane; cap response sizes.
- IdP lacks sender-constrained tokens or token exchange: documented fallback (short-lived tokens plus mTLS), recorded mode in tests (TC-G1).
- Detector quality below budget: keep advisory, rely on blast-radius controls (taint, approvals, egress).
- Hostile-fixture harness grows brittle: version fixtures and keep modes per case.
- Operational load of Kubernetes, mesh and admission choices: decide mesh versus certificate manager early (deployment architecture Section 17).

### 6.3 Phase 3: enterprise governance (about 8 weeks)

**Goal.** Fleet-level visibility and audit-ready evidence: governance workflows, a reviewed compliance mapping, and policy lifecycle controls.

**Deliverables**
- Fleet views: relationship graph, excessive-permission view, compliance posture, coverage gaps (FR-INV-6..7, FR-UI-5..6).
- Policy lifecycle: signed bundles, shadow mode, comparison reports (FR-POL-3..4); unused-permission and escalation reports (FR-AUTHZ-6..7).
- Scan governance: scheduled re-scans, finding lifecycle, rule-set update re-scan (FR-SCAN-7, 9); model registry and substitution alerts (FR-MOD-1); third-party intake (FR-SUP-3).
- Compliance engine: control catalogue loaded from `controls/`, mappings with status type and review dates, evidence packs signed and hash-listed, finding records (FR-COMP-1..5); incident reports (FR-IR-5).

**Dependencies.** Phase 2 exit; named legal and compliance reviewers; framework identifiers verified from primary sources; jurisdictions decided (PRD open question 6).

**Acceptance criteria**
- An auditor (internal or external) reviews a generated evidence pack for a chosen control and period and records findings; pack hashes verify.
- Compliance matrix reviewed and released with reviewer names and dates (FR-COMP-5); every mapping is labelled mandatory, guidance or voluntary.
- All 5 Phase 3 test cases pass: TC-L3, N2, X6, Z9, Z12; acceptance criteria AC-18 and AC-19 are met.
- Policy changes in staging pass through shadow mode with a recorded comparison before enforcement.

**Risks and mitigations**
- Mapping errors or overstatement: legal review gate; second-reviewer sampling; remove cells that cannot be defended.
- Framework changes during the phase: version each mapping; re-verify on change.
- Evidence generation depends on audit data quality from earlier phases: sample and replay decisions early in the phase (NFR-7).

### 6.4 Phase 4: advanced threat protection (about 12 weeks)

**Goal.** Cover the attack classes that need richer data or new components: memory poisoning, behaviour analytics, supply chain, inter-agent security and automated response.

**Deliverables**
- Memory and RAG integrity (FR-MEM-1..4) and model endpoint protection (FR-MOD-2..3).
- Behaviour baselines and anomaly scoring with explanations (FR-BEH-2); response-shape baselines for drift (FR-DRIFT-6).
- Supply chain: SBOM and vulnerability scanning of server artifacts, signing and admission enforcement for the server fleet, typosquat checks (FR-SCAN-5, FR-SUP-2, FR-SUP-4); agent-card verification (FR-ID-8).
- Tool execution hardening: sandbox profiles and upload checks (FR-EXEC-1..2).
- Inter-agent security: authenticated delegation, intersection of permissions, cycle and depth limits (FR-ID-4..6).
- Playbook automation with approval gates (FR-IR-4).

**Dependencies.** Phase 3 exit; measured detector data from Phase 2 for baselines; sandbox runtime decision; stable view of agent-to-agent protocols.

**Acceptance criteria**
- All 8 Phase 4 test cases pass: TC-J1, J2, L1, L2, M1, M2, N1, X9; acceptance criteria AC-20 and AC-21 are met.
- Red-team scenarios for memory poisoning, delegation abuse and supply-chain tampering are detected or contained, with results recorded; residual gaps are written into the threat model.
- Anomaly alert volume at or below the budget (5 reviewed alerts per 100 agents per day) in a pilot population.
- Automated playbooks run end to end in staging with human approval gates and produce an incident report.

**Risks and mitigations**
- ML false positives and alert fatigue: advisory only, tuning budgets, explanations.
- Agent protocol churn: isolate protocol handling behind an adapter; track versions in the compatibility matrix.
- Sandbox compatibility or overhead: pilot on selected servers first.
- Supply-chain tooling gaps (provenance of third-party servers): intake process and reporting before enforcement.

### 6.5 Phase 5: enterprise production (12+ weeks, open-ended)

**Goal.** Production-grade operation across clouds and regions with measured availability and independent assurance.

**Deliverables**
- Multi-cloud adapters and verified deployment per target cloud (deployment architecture Section 12).
- HA and DR with timed exercises; multi-region warm standby; residency pinning (FR-ADM-4; NFR-3, NFR-4, NFR-8; CTL-22, CTL-24).
- Enterprise integrations: SIEM and SOAR connectors, ticketing/chat for approvals, IdP federation options.
- Continuous validation: scheduled adversarial regression of the test catalogue, deployed-vs-signed checks, configuration drift detection.
- Per-tenant keys and optional dedicated tenancy models (deployment architecture Section 9).
- Red-team certification and external penetration test of the gateway and control plane (TC-X8).

**Dependencies.** Phase 4 exit; target cloud list and region/residency rules; customer SIEM/SOAR choices; budget for external testing.

**Acceptance criteria**
- Timed DR exercise meets RPO of 5 minutes or less and RTO of 30 minutes or less, and the restored audit chain verifies against the latest anchor (runbook Section 11).
- Measured availability meets the 99.95% monthly target over an agreed observation period.
- DA-1..DA-10 pass in each target environment; documented deviations exist for cloud capabilities that are unavailable.
- External penetration test reports no unremediated High or Critical findings; TC-X8 passes.
- Cross-tenant tests (TC-I3) pass in every tenancy model offered.
- Red-team certification criteria are written and met (criteria do not yet exist, see finding F3).

**Risks and mitigations**
- Operational maturity (on-call, runbooks, exercises) lags engineering: run game days from Phase 2; staff the on-call rotation before Phase 5.
- Residency and audit chain conflict across regions: active/passive per tenant by default; separate design for any active/active.
- Cloud feature gaps (object lock, sandbox runtimes, workload identity): per-cloud verification and recorded deviations.
- Open-ended integration scope: define a launch list of integrations per customer.

## 7. Allocation summary

| Phase | Requirement IDs tagged to the phase (spec) |
|---|---|
| 1 | FR-INV-1..4; FR-SCAN-1..4, 6; FR-DRIFT-1..5; FR-ID-1..2; FR-AUTHN-1, 6; FR-AUTHZ-1..3, 8; FR-RT-1; FR-SSRF-1..5; FR-MCP-4; FR-POL-1..2; FR-AUD-1..2, 6; FR-UI-1..3, 7; FR-ADM-1; FR-OBS-1; FR-DATA-1..2 |
| 2 | FR-INV-5; FR-SCAN-8, 10; FR-DRIFT-7; FR-ID-3, 7; FR-AUTHN-2..5, 7; FR-AUTHZ-4..5, 9..12; FR-RT-2..13; FR-AUTO-1..6; FR-SUP-1; FR-MCP-1..3, 5..12; FR-AUD-3..5, 7; FR-BEH-1; FR-IR-1..3; FR-UI-4; FR-ADM-2..3, 5..8; FR-OBS-2; FR-DATA-3..4; FR-KEY-1..5 |
| 3 | FR-INV-6..7; FR-SCAN-7, 9; FR-AUTHZ-6..7; FR-MOD-1; FR-SUP-3; FR-POL-3..4; FR-IR-5; FR-UI-5..6; FR-COMP-1..5 |
| 4 | FR-SCAN-5; FR-DRIFT-6; FR-ID-4..6, 8; FR-MEM-1..4; FR-MOD-2..3; FR-EXEC-1..2; FR-SUP-2, 4; FR-BEH-2; FR-IR-4 |
| 5 | FR-ADM-4; FR-KEY-6 (plus NFR-3, 4, 5, 8) |

Control phases follow `controls/catalogue.yaml`; several controls span phases (for example CTL-03 P1/P2, CTL-22 P2/P5), and a control is complete only when its last phase is done.

## 8. Team, cost and re-baselining

Assumed core roles (not confirmed): backend/platform engineers (2), security engineer for scanner and detectors (1, may be one of the backend engineers), frontend engineer (part-time in Phases 1 and 3), DevSecOps engineer (part-time from Phase 1, full from Phase 2), security architect (part-time), compliance/legal reviewers (part-time from Phase 2), red-team or external testers (from Phase 2 gates).

Re-baselining points: after Phase 0 spikes (before committing Phase 2 dates); after Phase 1 (actual velocity versus plan); at each phase gate. Estimates for Phases 3 to 5 should be treated as order-of-magnitude until then. Cost is not estimated because team, cloud and tooling choices are open.

## 9. Findings from preparing this roadmap (cross-document issues to resolve)

| # | Finding | Why it matters | Suggested resolution |
|---|---|---|---|
| F1 | TC-Z6 (audit tamper detection) is tagged Phase 1 MVP and maps to AC-5, but its steps include detecting a full-chain rewrite against an external anchor, and anchoring (FR-AUD-4) is tagged Phase 2 | The MVP acceptance test cannot pass without anchoring | Either deliver minimal anchoring in Phase 1, or split TC-Z6 into a chain-verification part (P1) and an anchor part (P2); **resolved in test catalogue v0.3 (TC-Z6 split, TC-Z22 added)** |
| F2 | Signing and admission of images (FR-SUP-1, TC-L2) are tagged Phase 4, but the CI/CD pipeline and deployment architecture place signing in CI stage 2 and admission verification in Phase 2 environments (DA-3) | Release security would lag the pipeline design by two phases | Decide: retag FR-SUP-1 to Phase 2 for the platform's own images and keep Phase 4 for the server fleet, or accept unsigned images in Phase 2 with a recorded waiver; **resolved in spec v0.4 (FR-SUP-1 retagged to P2, FR-SUP-4 added) and test catalogue v0.3 (TC-L4)** |
| F3 | Phase 5 has one tagged requirement (FR-ADM-4); multi-cloud adapters, SIEM/SOAR integrations, continuous validation and red-team certification have no requirements or acceptance criteria | Phase 5 cannot be accepted or estimated | Add requirements and certification criteria before Phase 3 exit |
| F4 | The Phase 0 spikes S1..S6 (about 8 weeks) and verification of `[VERIFY]` items are not in any phase duration | Phase 2 start dates are optimistic | Schedule spikes inside Phase 0/1 and re-baseline Phase 2 afterwards; **schedule proposed in Section 4.1, pending approval** |
| F5 | ADR-3, ADR-4 and ADR-6 are open but gate Phase 1 | Phase 1 cannot start cleanly | Decide in Phase 0 review |
| F6 | The e2e harness, hostile fixtures and Compose environment are required by the MVP test cases but do not exist | Hidden effort in Phase 1 | Treat as an explicit Phase 1 deliverable (done in 6.1) |
| F7 | Requirements without dedicated test cases: FR-SCAN-9, FR-AUD-7, FR-ADM-6 | Acceptance for P2/P3 incomplete | Add cases during the owning phase (listed in 6.2 and 6.3 acceptance); **resolved in test catalogue v0.3 (TC-Z12, TC-Z23, TC-Z24)** |
| F8 | Team size, skills and cost are assumptions | All estimates depend on them | Confirm in Phase 0 sign-off |

These findings are recorded here only; the other documents have not been changed.

## 10. Phase gate checklist (applies to every phase)

1. Acceptance criteria met, with evidence stored (test results, load-test reports, review records).
2. No open Critical or High defect or finding without an approved, time-boxed waiver.
3. Requirements tagged to the phase are implemented or explicitly re-tagged with approval; the spec, catalogue and test catalogue are updated and `scripts/check_docs.py` passes.
4. Runbook and playbooks updated for new components; new alerts and dashboards exist and fire in staging.
5. Threat model and residual risks updated for what actually shipped.
6. Compliance matrix and control catalogue statuses updated (status moves from specified to implemented only with evidence).
7. Security review sign-off, including a check that fail-closed behaviour still holds (TC-Z5).
8. Go/no-go decision recorded with approvers who are not the delivery team lead alone.
9. Re-baseline of remaining phase estimates.

## 11. Out of scope for this roadmap

Pricing, packaging, commercial go-to-market, hiring plans, vendor negotiation, and any customer-specific rollout plan. A pilot design (which business unit, how many agents and servers) is an open question in the PRD (Section 12) and should be added before Phase 1 exit.

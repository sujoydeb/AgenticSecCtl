# Compliance Mapping Matrix: AgenticSecCtl

| | |
|---|---|
| Version | 0.1 (draft; **not reviewed by legal or compliance**) |
| Depends on | `Plan/functional-spec.md` v0.3, `Plan/architecture.md` v0.2, `Plan/threat-model.md` v0.2, `docs/testing/cases.md` v0.2, `docs/runbooks/operational-runbook.md` v0.2, `docs/playbooks/incident-response-playbooks.md` v0.1, `docs/tech-evaluation.md` v0.1 |
| Satisfies | FR-COMP-1..3 (control catalogue, mandatory/guidance/voluntary labelling, per-finding record). FR-COMP-5 (legal review before release) is **not yet satisfied**. |
| Review status | Review date: none. Reviewer: none. Release as an authoritative mapping is blocked until reviewed. |

## 1. Read this first

1. **A mapping is not compliance.** This matrix says which platform controls *support* which framework items by providing evidence or technical measures. It does not assert that any organisation, system or deployment complies with any law, regulation, guidance or standard. Compliance depends on the organisation's scope, role, processes, other controls and legal interpretation.
2. **Framework references are unverified.** Web research to confirm current article, clause and control identifiers was blocked during authoring (see `docs/tech-evaluation.md` verification log). Every identifier below comes from background knowledge and is marked as unverified at framework level in Section 2. Editions and numbering change (for example, annexes, control sets, guidance status). Verify each against the official text before relying on it.
3. **Three kinds of source are kept apart** (FR-COMP-2):
   - **Mandatory law/regulation or contractual/industry mandate** (EU AI Act, GDPR, DORA, PCI DSS where in scope).
   - **Supervisory guidance** (SR 11-7, FFIEC): expected by examiners, not statute.
   - **Voluntary frameworks and standards** (NIST, ISO, SOC 2) and **community/knowledge bases** (OWASP, MITRE).
4. **Applicability is conditional.** Many mandatory provisions apply only to certain roles (provider, deployer, controller, processor, financial entity) and risk classes (for example, high-risk AI systems). The platform is a security control layer for an organisation's agents; it is not itself assumed to be a regulated AI system. Section 6 states the shared-responsibility limits.
5. **Control status is design-stage.** All controls are specified, none implemented. "Remediation status" in the findings register reflects that.

## 2. Framework register

| ID | Framework | Source type (FR-COMP-2) | Applies when | Edition to confirm | Verified |
|---|---|---|---|---|---|
| F-EUAI | EU AI Act (Regulation (EU) 2024/1689) | **Mandatory law** | Organisation is a provider/deployer/importer etc. of AI systems in scope; obligations depend on role and risk class (high-risk, GPAI) | Consolidated text and application dates | No |
| F-GDPR | GDPR (Regulation (EU) 2016/679) | **Mandatory law** | Processing personal data of people in the EU/EEA (or UK equivalents where relevant) | Current text | No |
| F-DORA | DORA (Regulation (EU) 2022/2554) | **Mandatory law** (EU financial entities and ICT third-party providers in scope) | Entity is in DORA scope | Regulation plus technical standards | No |
| F-PCI | PCI DSS | **Contractual/industry mandate** (via card brand and acquirer agreements) | Cardholder data environment or connected systems in scope | v4.x (confirm exact version) | No |
| F-SR117 | SR 11-7 / OCC 2011-12 Supervisory Guidance on Model Risk Management | **Supervisory guidance** | US banking organisations; models include AI/ML used in decisioning | Current guidance | No |
| F-FFIEC | FFIEC IT Examination Handbook booklets and related guidance | **Supervisory guidance** | US financial institutions | Current booklet set; confirm status of any retired tools | No |
| F-CSF | NIST Cybersecurity Framework | **Voluntary framework** (can be mandated by contract or policy) | Any | CSF 2.0 | No |
| F-AIRMF | NIST AI Risk Management Framework 1.0 | **Voluntary framework** | Any | 1.0 (confirm updates) | No |
| F-AI600 | NIST AI 600-1 Generative AI Profile | **Voluntary profile** | Organisations using generative AI | July 2024 edition (confirm) | No |
| F-ISO27001 | ISO/IEC 27001 | **Voluntary standard** (certifiable) | Organisations with or seeking certification | 2022 edition; Annex A numbering | No |
| F-ISO42001 | ISO/IEC 42001 AI management system | **Voluntary standard** (certifiable) | Organisations with or seeking certification | 2023 edition | No |
| F-ISO23894 | ISO/IEC 23894 AI risk management guidance | **Voluntary guidance** (not certifiable) | Any | 2023 edition | No |
| F-SOC2 | SOC 2 Trust Services Criteria | **Voluntary attestation framework** | Service organisations reporting to customers | Current TSC revision | No |
| F-OWLLM | OWASP Top 10 for LLM Applications | **Community guidance** | Any | 2025 edition (confirm) | No |
| F-OWMCP | OWASP MCP Top 10 | **Community guidance** | Any | Project existence verified; entry identifiers not retrieved; licence reported as CC BY-NC-SA 4.0 | Partly (existence only) |
| F-ATLAS | MITRE ATLAS | **Knowledge base** | Any | Current matrix and technique IDs | No |
| F-ATTCK | MITRE ATT&CK | **Knowledge base** | Any | Enterprise matrix version | No |

## 3. Control catalogue

Controls are platform capabilities. Types: **P** prevent, **D** detect, **R** respond, **V** recover. "Owner" is the role accountable for the control operating effectively, not a named person (to be assigned). Evidence lists what an auditor would ask for; the platform produces it per FR-COMP-4 once built.

| ID | Control | Type | Component | Requirements | Tests | Evidence required | Owner (role) | Phase |
|---|---|---|---|---|---|---|---|---|
| CTL-01 | Inventory and registration of agents, servers and tools with owner, environment, criticality | P, D | Registry/API | FR-INV-1..4, FR-ID-1/2 | TC-C1, TC-C3, TC-F1 | Inventory export; registration approvals; unregistered-asset reports | Security engineering | P1 |
| CTL-02 | Tool scanning with reproducible scoring; approval with separation of duties and dual-control override | P, D | Scanner, Registry | FR-SCAN-1..4, 6, 9 | TC-A1..A5, TC-E4, TC-Z2 | Scan reports with rule-set version; approval and override records | Security engineering | P1 |
| CTL-03 | Definition pinning (canonical hash) and drift quarantine | P, D, R | Gateway, Registry | FR-DRIFT-1..7 | TC-B1..B4, TC-Z3 | Version history; hash records; drift events; quarantine records | Security engineering | P1/P2 |
| CTL-04 | Agent identity and credential lifecycle (unique identity, rotation, revocation, deny on revocation-lookup failure) | P, R | Identity/broker | FR-ID-1..3, 7 | TC-F1, TC-F2, TC-G1 | Client registry; rotation and revocation logs | Identity and access team | P1/P2 |
| CTL-05 | Authentication hardening: audience/scope validation, sender-constrained tokens, no token passthrough, session binding, server identity validation, secret redaction | P, D | Gateway, broker | FR-AUTHN-1..6 | TC-F2, TC-G1..G5, TC-C2 | Token validation configuration; deny logs; redaction test results | Identity and access team | P1/P2 |
| CTL-06 | Least-privilege authorization, deny by default, action classes, agent→server allowlists, unused-permission and escalation reporting | P, D | PDP, Gateway | FR-AUTHZ-1..3, 6..8 | TC-E1, TC-E2, TC-C3, TC-Z5 | Policy bundles with hashes; decision logs; permission reviews | Security engineering | P1/P2/P3 |
| CTL-07 | Just-in-time access and human approval for high-impact actions bound to argument hash | P | PDP, API | FR-AUTHZ-4/5, FR-AUTO-3 | TC-E3, TC-D4, TC-K3 | Grant and approval records with approver identity | Business owner and approver pool | P2 |
| CTL-08 | SSRF protection and egress allowlisting | P, D | Egress proxy, Scanner | FR-SSRF-1..5, FR-RT-7 | TC-H1..H4, TC-I4, TC-X2 | Guard configuration; blocked-connection logs; network policy exports | Platform security | P1/P2 |
| CTL-09 | Response inspection for injection, untrusted labelling, taint rule | P, D | Gateway, Inspection | FR-RT-4, 5, 9, 11 | TC-D1..D5 | Detector configuration; shadow-mode results; signals log | Security engineering | P2 |
| CTL-10 | Data loss prevention on requests and responses; tenant isolation | P, D | Gateway, DLP | FR-RT-6, 8, FR-AUD-3 | TC-I1..I3, TC-G5 | DLP policies; match logs; isolation test results | Data protection / security engineering | P2 |
| CTL-11 | Argument guards, schema validation, execution sandboxing | P | Gateway, platform | FR-RT-2, 3, FR-EXEC-1/2 | TC-O1..O3, TC-Z1 | Guard rules; sandbox profiles; test results | Platform security | P2/P4 |
| CTL-12 | Autonomy limits, budgets, loop detection, kill switch with different-approver resume | P, D, R | Gateway, API | FR-AUTO-1..5, FR-ID-5, FR-RT-10 | TC-K1..K3, TC-M1, TC-Z4 | Limit configuration; suspension and resume records | Security engineering | P2 |
| CTL-13 | Tamper-evident audit: hash chain, external anchoring, reproducible decisions, deny-high-impact when audit cannot record | D | Audit service | FR-AUD-1..7 | TC-Z6, TC-X5 | Chain verification reports; anchor records; sample decision replays | Security operations / audit liaison | P1/P2 |
| CTL-14 | Security monitoring and alerting; platform observability | D | Analytics, observability | FR-BEH-1/2, FR-OBS-1/2 | TC-K1, TC-P4 | Alert rules; on-call records; SLO reports | Security operations | P2/P4 |
| CTL-15 | Incident detection, containment, evidence preservation, reporting | R, V | Incident manager | FR-IR-1..5 | Playbook exercises (see playbooks Section 7.3), TC-X8 | Incident records; evidence index; post-incident reviews | Incident commander / security operations | P2/P3/P4 |
| CTL-16 | Policy lifecycle: source control and review, signed bundles, shadow mode | P | PDP, CI | FR-POL-1..4 | TC-X6 | Change records; bundle signatures; review approvals | Security engineering | P1/P3 |
| CTL-17 | Supply-chain security: SBOM, vulnerability scanning, signing/provenance, third-party intake | P, D | CI, scanner, admission | FR-SCAN-5, FR-SUP-1..3, FR-MOD-3, NFR-9 | TC-L1..L3 | SBOMs; scan reports; signature verification logs; intake records | Platform security | P3/P4 |
| CTL-18 | MCP lifecycle controls: version allowlist, capability limits, sampling/elicitation default-deny, roots, notifications | P | Gateway | Spec Section 4.12 | TC-P1..P4 | Protocol configuration; compatibility matrix; deny logs | Security engineering | P2 |
| CTL-19 | Memory and RAG integrity: attributed writes, provenance labels, partitions, rollback | P, D, V | Memory tools, Inspection | FR-MEM-1..4 | TC-J1, TC-J2 | Write attribution logs; rollback records | Security engineering | P4 |
| CTL-20 | Inter-agent security: authenticated delegation, no privilege amplification, cycle/depth limits | P | Gateway, PDP | FR-ID-4..6 | TC-M1, TC-M2 | Delegation logs; policy tests | Security engineering | P4 |
| CTL-21 | Model registry and endpoint protection: approved model pinning, substitution detection, quotas | P, D | Registry, Gateway | FR-MOD-1..3 | TC-N1, TC-N2 | Model registry; quota and alert logs | AI governance / model owner | P3/P4 |
| CTL-22 | Multi-tenancy, data residency and retention | P | Platform | FR-ADM-2, 4, 5, FR-RT-8 | TC-I3 | Tenant configuration; retention reports; residency settings | Data protection / platform ops | P2/P5 |
| CTL-23 | Separation of duties, privileged and break-glass access | P, D | API, IdP | SoD-1..3, FR-ADM-6, FR-UI-7 | TC-E4, TC-X6, TC-X8 | Role bindings; access reviews; break-glass use records | Security administration | P1/P2 |
| CTL-24 | Resilience: fail-closed behaviour, HA, backup, DR testing | P, V | Platform | FR-AUTHZ-8, FR-AUD-7, NFR-3/4 | TC-Z5, TC-Z6; DR exercises (runbook Section 11) | HA design; backup and restore test records; DR exercise reports | Platform operations | P1/P5 |
| CTL-25 | Compliance evidence generation and framework mapping governance | D | Compliance engine | FR-COMP-1..5 | Evidence pack review | Signed evidence packs; mapping review records | Compliance liaison | P3 |
| CTL-26 | Discovery and coverage reporting (known gaps) | D | Discovery | FR-INV-5..7 | TC-X2 | Discovery results; coverage-gap reports | Security engineering | P2/P3 |
| CTL-27 | Secure development and change management for the platform | P | CI/CD, process | NFR-9; runbook Section 6 | TC-L3 | CI gate results; change approvals; pen-test reports | Engineering management / platform security | P1 onward |

## 4. Control-to-framework mapping

Cell entries are *candidate supporting references*. "—" means no meaningful direct relationship was identified. All identifiers are **unverified** (Section 2).

### 4.1 Mandatory law/regulation and contractual mandates (F-EUAI, F-GDPR, F-DORA, F-PCI)

| Control | EU AI Act | GDPR | DORA | PCI DSS (if in scope) |
|---|---|---|---|---|
| CTL-01 Inventory | Art. 26 (deployer duties; knowing which AI systems are in use) | Art. 30 (records of processing; inventory input) | Art. 8 (identification, asset inventory) | Req. 12.5 (scope/inventory of in-scope systems; confirm numbering) |
| CTL-02 Scanning/approval | Art. 9, 15 (risk management, cybersecurity; for high-risk systems) | Art. 25, 32 | Art. 9, 28 (protection; third-party risk) | Req. 6 |
| CTL-03 Pinning/drift | Art. 15 | Art. 32 (integrity) | Art. 9 (change and integrity controls) | Req. 6 (change control), Req. 11.5 (change detection; confirm) |
| CTL-04 Identity lifecycle | Art. 15 | Art. 32 | Art. 9 | Req. 8 |
| CTL-05 Authentication | Art. 15 | Art. 32 | Art. 9 | Req. 8 |
| CTL-06 Authorization | Art. 14, 15 | Art. 5(1)(c), 25, 32 | Art. 9 | Req. 7 |
| CTL-07 JIT / human approval | Art. 14 (human oversight), Art. 26 | Art. 22 (where decisions with legal/similar effect are involved), Art. 25 | Art. 9, 11 | Req. 7 |
| CTL-08 SSRF/egress | Art. 15 | Art. 32 | Art. 9 | Req. 1 |
| CTL-09 Injection handling | Art. 15 (resilience to manipulation of inputs) | Art. 32 | Art. 9, 10 | Req. 6 |
| CTL-10 DLP/tenant isolation | Art. 10 (data governance; where applicable), Art. 15 | Art. 5(1)(c)(f), 25, 32, Ch. V (transfers) | Art. 9 | Req. 3, 4 |
| CTL-11 Argument guards/sandbox | Art. 15 | Art. 32 | Art. 9 | Req. 6 |
| CTL-12 Autonomy limits | Art. 14, 15 | Art. 24, 25 | Art. 9 | — |
| CTL-13 Audit | Art. 12 (record-keeping; high-risk), Art. 26 (log retention by deployers) | Art. 5(2) (accountability), 30, 32 | Art. 10, 12; Art. 13 (learning) | Req. 10 |
| CTL-14 Monitoring | Art. 72 (post-market monitoring; providers), Art. 26 | Art. 32 | Art. 10 | Req. 10, 11 |
| CTL-15 Incident response | Art. 73 (serious incidents; providers), Art. 26 | Art. 33, 34 (personal data breach) | Art. 11, 17..19 (response, incident management/reporting) | Req. 12.10 |
| CTL-16 Policy lifecycle | Art. 17 (quality management; providers) | Art. 24 | Art. 6 (ICT risk framework) | Req. 12 |
| CTL-17 Supply chain | Art. 25 (value-chain responsibilities) | Art. 28 (processors) | Art. 28..30 (third-party risk) | Req. 6, 12.8 |
| CTL-18 MCP lifecycle | Art. 15 | Art. 32 | Art. 9 | — |
| CTL-19 Memory/RAG integrity | Art. 10, 15 | Art. 5(1)(d) (accuracy), 32 | Art. 9 | — |
| CTL-20 Inter-agent | Art. 14, 15 | Art. 32 | Art. 9 | — |
| CTL-21 Model registry | Art. 11, 17 (documentation, QMS); Art. 55 (GPAI with systemic risk; cyber protection) | — | Art. 8 | — |
| CTL-22 Tenancy/residency/retention | Art. 12 (retention), Art. 26 | Art. 5(1)(e), 25, 28, Ch. V | Art. 9, 12 | Req. 3 |
| CTL-23 SoD/privileged access | Art. 15 | Art. 32 | Art. 9 | Req. 7, 8 |
| CTL-24 Resilience | Art. 15 | Art. 32(1)(b)(c) | Art. 11, 12; Art. 24..26 (testing) | Req. 12.10 (readiness), Req. 11 |
| CTL-25 Compliance evidence | Art. 11, 12 (documentation, logs) | Art. 5(2), 24, 30 | Art. 6; Art. 17..19 | Req. 12 |
| CTL-26 Discovery/coverage | Art. 26 | Art. 30 | Art. 8 | Req. 12.5 |
| CTL-27 Secure development/change | Art. 15, 17 | Art. 25, 32 | Art. 9; Art. 16 (simplified framework) | Req. 6 |

### 4.2 Supervisory guidance (F-SR117, F-FFIEC)

| Control | SR 11-7 / OCC 2011-12 | FFIEC IT Examination Handbook (booklets) |
|---|---|---|
| CTL-01 Inventory | Model inventory and governance (inventory of models including AI/ML in use) | Information Security; Management |
| CTL-02 Scanning/approval | Development, implementation and use controls; independent review | Development, Acquisition and Maintenance |
| CTL-03 Pinning/drift | Change control, ongoing monitoring of model/component changes | Development, Acquisition and Maintenance; Information Security |
| CTL-04 Identity lifecycle | — (supporting) | Information Security (access management) |
| CTL-05 Authentication | — (supporting) | Information Security (authentication) |
| CTL-06 Authorization | Controls over model use and access | Information Security (access control) |
| CTL-07 JIT / human approval | Governance: human judgement and effective challenge in model use | Information Security; Management |
| CTL-08 SSRF/egress | — | Information Security (network security) |
| CTL-09 Injection handling | Model risk: input integrity and limitations of use | Information Security |
| CTL-10 DLP/tenant isolation | Data quality and confidentiality aspects of model inputs | Information Security; Outsourcing Technology Services |
| CTL-11 Argument guards/sandbox | — | Information Security; Architecture, Infrastructure and Operations |
| CTL-12 Autonomy limits | Limits and monitoring of model use; override | Information Security; Management |
| CTL-13 Audit | Documentation and audit trail supporting validation and governance | Audit; Information Security |
| CTL-14 Monitoring | Ongoing monitoring (outcomes, drift, performance) | Information Security; Architecture, Infrastructure and Operations |
| CTL-15 Incident response | — (supporting) | Information Security; Business Continuity Management |
| CTL-16 Policy lifecycle | Policies, procedures and controls over models | Management; Information Security |
| CTL-17 Supply chain | Vendor/third-party model and component risk | Outsourcing Technology Services; Development, Acquisition and Maintenance |
| CTL-18 MCP lifecycle | — | Information Security |
| CTL-19 Memory/RAG integrity | Data and assumption integrity (model inputs) | — |
| CTL-20 Inter-agent | — | — |
| CTL-21 Model registry | Model inventory, versioning and approved use | Management |
| CTL-22 Tenancy/residency/retention | Documentation retention | Outsourcing Technology Services; Information Security |
| CTL-23 SoD/privileged access | Independence of validation from development | Information Security (privileged access); Audit |
| CTL-24 Resilience | — (supporting) | Business Continuity Management; Architecture, Infrastructure and Operations |
| CTL-25 Compliance evidence | Documentation and reporting to senior management/board | Audit; Management |
| CTL-26 Discovery/coverage | Complete inventory of models in use (shadow AI) | Information Security; Management |
| CTL-27 Secure development/change | Implementation controls; testing before use | Development, Acquisition and Maintenance |

Note: SR 11-7 expects model validation (conceptual soundness, outcomes analysis) by qualified independent staff. **The platform does not perform model validation** (Section 6).

### 4.3 Voluntary frameworks and standards

| Control | NIST CSF 2.0 | NIST AI RMF 1.0 / AI 600-1 | ISO/IEC 27001:2022 Annex A | ISO/IEC 42001 / 23894 | SOC 2 TSC |
|---|---|---|---|---|---|
| CTL-01 | ID.AM | GOVERN; MAP (inventory of AI systems); AI 600-1: value chain and component integration | A.5.9 (inventory of information and assets) | 42001 Annex A (AI system inventory/lifecycle); 23894 risk identification | CC2, CC3 |
| CTL-02 | ID.RA, PR.PS | MAP, MEASURE; AI 600-1: information security | A.8.8 (technical vulnerabilities), A.8.28 (secure coding) | 42001 AI system life cycle; 23894 risk assessment | CC3, CC7 |
| CTL-03 | PR.PS, DE.CM | MEASURE, MANAGE | A.8.9 (configuration management), A.8.32 (change management) | 42001 life cycle | CC8 |
| CTL-04 | PR.AA | GOVERN | A.5.16 (identity management), A.5.17, A.8.5 | 42001 resources/roles | CC6 |
| CTL-05 | PR.AA | MANAGE; AI 600-1: information security | A.5.17, A.8.5 (secure authentication), A.8.24 (cryptography) | — | CC6 |
| CTL-06 | PR.AA | GOVERN, MANAGE | A.5.15 (access control), A.5.18, A.8.3 | 42001 use of AI systems | CC6 |
| CTL-07 | PR.AA, GV.RR | GOVERN; MANAGE; AI 600-1: human-AI configuration | A.5.3 (segregation of duties), A.5.15 | 42001 human oversight/controls; 23894 treatment | CC6, CC5 |
| CTL-08 | PR.IR | MANAGE | A.8.20 (network security), A.8.22 (segregation of networks), A.8.23 (web filtering) | — | CC6 |
| CTL-09 | PR.PS, DE.CM | MEASURE, MANAGE; AI 600-1: information security | A.8.7 (protection against malware; analogous), A.8.26 | 23894 risk treatment | CC6, CC7 |
| CTL-10 | PR.DS | MANAGE; AI 600-1: data privacy | A.8.12 (data leakage prevention), A.5.12/5.13 (classification, labelling), A.8.11 (masking) | 42001 data for AI systems | C1, P (privacy criteria) |
| CTL-11 | PR.PS | MANAGE | A.8.26 (application security requirements), A.8.28, A.8.29 (security testing) | — | CC6, CC7 |
| CTL-12 | PR.PS, GV.OC | MANAGE; AI 600-1: human-AI configuration | A.8.6 (capacity management; analogous) | 42001 controls for AI use | CC7 |
| CTL-13 | DE.CM, PR.PS | MEASURE | A.8.15 (logging), A.8.17 (clock synchronisation) | 42001 records/logs | CC7 |
| CTL-14 | DE.CM, DE.AE | MEASURE | A.8.16 (monitoring activities) | 23894 monitoring and review | CC7 |
| CTL-15 | RS.MA, RS.AN, RS.MI, RS.CO, RC.RP | MANAGE (incident response); AI 600-1 | A.5.24..A.5.28 (incident management) | 42001 incident handling | CC7 |
| CTL-16 | GV.PO | GOVERN | A.5.1 (policies), A.8.32 | 42001 policies | CC1, CC5 |
| CTL-17 | GV.SC, ID.RA | GOVERN, MAP; AI 600-1: value chain and component integration | A.5.19..A.5.23 (supplier relationships and cloud services) | 42001 third-party relationships | CC9 |
| CTL-18 | PR.PS | MANAGE | A.8.26 | — | CC6 |
| CTL-19 | PR.DS | MEASURE, MANAGE; AI 600-1: information integrity | A.8.3, A.8.10 (information deletion; rollback context) | 42001 data | CC6, PI (processing integrity, if in scope) |
| CTL-20 | PR.AA | MANAGE | A.5.15, A.8.3 | — | CC6 |
| CTL-21 | ID.AM, GV.SC | GOVERN, MAP | A.5.9 | 42001 AI system inventory/lifecycle | CC3, CC8 |
| CTL-22 | PR.DS, GV.OC | MANAGE; AI 600-1: data privacy | A.5.33 (protection of records), A.5.34 (privacy and PII), A.8.10 | 42001 data governance | C1, P |
| CTL-23 | PR.AA | GOVERN | A.5.3, A.8.2 (privileged access rights) | — | CC6 |
| CTL-24 | PR.IR, RC.RP | MANAGE | A.5.29, A.5.30 (ICT readiness for business continuity), A.8.13, A.8.14 (backup, redundancy) | — | A1 |
| CTL-25 | GV.OV | GOVERN | A.5.35, A.5.36 (independent review; compliance with policies) | 42001 performance evaluation, internal audit | CC4 |
| CTL-26 | ID.AM | MAP | A.5.9 | 42001 inventory | CC3 |
| CTL-27 | PR.PS | MANAGE | A.8.25..A.8.32 | 42001 life cycle | CC8 |

### 4.4 Community guidance and knowledge bases by threat

Linked to threats in `Plan/threat-model.md`. OWASP MCP entry identifiers are **not recorded**: the project exists, but its entry list was not retrieved. MITRE identifiers are from background knowledge; confirm names and numbers.

| Threat | OWASP LLM Top 10 (2025; confirm) | OWASP MCP Top 10 | MITRE ATLAS (technique, confirm ID) | MITRE ATT&CK (technique, confirm ID) |
|---|---|---|---|---|
| A Tool poisoning | LLM01 Prompt Injection; LLM03 Supply Chain | Entry TBD | LLM prompt injection (AML.T0051) | — |
| B Rug pull/drift | LLM03 Supply Chain | Entry TBD | ML supply chain compromise (AML.T0010) | T1195 Supply Chain Compromise |
| C Shadowing/impersonation | LLM03 Supply Chain | Entry TBD | — | T1036 Masquerading |
| D Response injection | LLM01 Prompt Injection; LLM05 Improper Output Handling | MCP10 context injection and over-sharing (name per secondary source; confirm) | LLM prompt injection (AML.T0051) | — |
| E Excessive permissions | LLM06 Excessive Agency | Entry TBD | — | T1078 Valid Accounts; T1098 Account Manipulation |
| F Agent spoofing | LLM06 Excessive Agency | Entry TBD | — | T1078 Valid Accounts |
| G Auth attacks | LLM02 Sensitive Information Disclosure; LLM06 | Token mismanagement and secret exposure (name per secondary source; confirm) | — | T1528 Steal Application Access Token; T1550 Use Alternate Authentication Material; T1552 Unsecured Credentials |
| H SSRF | LLM06 Excessive Agency | Entry TBD | — | T1552.005 Cloud Instance Metadata API; T1190 Exploit Public-Facing Application |
| I Exfiltration | LLM02 Sensitive Information Disclosure | MCP10 (over-sharing) | Exfiltration via ML inference API (AML.T0024; applicability partial) | T1041 Exfiltration Over C2 Channel; T1567 Exfiltration Over Web Service |
| J Memory/RAG poisoning | LLM04 Data and Model Poisoning; LLM08 Vector and Embedding Weaknesses | Entry TBD | Poison training data (AML.T0020; applicability partial) | T1565 Data Manipulation |
| K Autonomy abuse | LLM06 Excessive Agency; LLM10 Unbounded Consumption | Entry TBD | — | T1499 Endpoint Denial of Service (analogous) |
| L Supply chain | LLM03 Supply Chain | Entry TBD | ML supply chain compromise (AML.T0010) | T1195 Supply Chain Compromise |
| M Inter-agent | LLM01; LLM06 | Entry TBD | — | T1021 Remote Services (analogous) |
| N Model/inference | LLM10 Unbounded Consumption; LLM02 | — | Model extraction techniques (confirm IDs) | — |
| O Tool execution | LLM05 Improper Output Handling | Entry TBD | — | T1059 Command and Scripting Interpreter; T1611 Escape to Host; T1190 |
| P MCP protocol | LLM06 | Entry TBD | — | — |
| X5 Log injection | LLM05 | Entry TBD | — | T1070 Indicator Removal (analogous) |
| X6 Insider approval | LLM06 | Entry TBD | — | T1078 Valid Accounts |
| X8 Gateway compromise | LLM03 | Entry TBD | — | T1190; T1611; T1078 |

## 5. Findings register (threat-level)

One record per threat, with the nine fields required by the brief. Risk ratings are copied from `Plan/threat-model.md` (inherent / residual, qualitative judgments, not measurements). **Remediation status for every row is "Design only; control specified, not implemented"** with the first delivery phase in brackets. Control owner roles are proposals.

| Finding | Threat description | Affected component | Applicable controls | Regulatory/framework mapping (see Section 4; status in Section 2) | Risk (inherent / residual) | Recommended mitigation | Evidence required | Control owner | Remediation status |
|---|---|---|---|---|---|---|---|---|---|
| FND-A | Tool descriptions or metadata carry hidden or override instructions | Registry, Scanner, Gateway | CTL-02, 03, 06, 09 | DORA Art. 9; GDPR Art. 32; EU AI Act Art. 15 (if in scope); OWASP LLM01/03; ISO 27001 A.8.8/8.28; NIST CSF PR.PS | High / Medium | Scan with deterministic rules, dual-control override of Critical, hash-pinned approval, filtered `tools/list` | Scan reports with rule-set version, approvals, `tools/list` logs, TC-A1..A5 results | Security engineering | Design only (P1) |
| FND-B | Approved tool changes silently (rug pull) | Gateway, Registry | CTL-03, 12, 13 | DORA Art. 9; ISO 27001 A.8.9/8.32; NIST CSF PR.PS/DE.CM; SOC 2 CC8; SR 11-7 change control | High / Medium | Call-time and list-time hash checks, auto-quarantine, behaviour baselines | Drift events, version history, TC-B1..B4, TC-Z3 | Security engineering | Design only (P1/P2) |
| FND-C | Duplicate names or impersonating servers redirect calls | Registry, Gateway | CTL-01, 05, 06 | ISO 27001 A.5.16/A.5.17/A.8.5; NIST CSF PR.AA; DORA Art. 28 (third parties) | High / Low-Medium | Namespacing, pinned server identity, agent→server allowlists | Registry export, TLS pin records, TC-C1..C3 | Security engineering | Design only (P1/P2) |
| FND-D | Injection via tool responses or retrieved content causes unintended actions | Gateway, Inspection, PDP | CTL-07, 09, 12 | EU AI Act Art. 14/15 (if in scope); OWASP LLM01/05; AI 600-1 information security; NIST AI RMF MANAGE | Critical / Medium-High | Untrusted labelling, taint rule, approvals for high-impact actions, egress limits, shadow-mode tuning | Signals log, approval records, red-team results TC-D1..D5 | Security engineering | Design only (P2) |
| FND-E | Over-broad or escalated agent permissions | PDP, API | CTL-06, 07, 23 | PCI DSS Req. 7/8; GDPR Art. 5(1)(c), 25; ISO 27001 A.5.15/5.18/8.2; SOC 2 CC6; NIST CSF PR.AA; OWASP LLM06 | High / Medium | Least privilege, JIT, SoD, unused-permission reviews | Policy bundles, decision logs, access reviews, TC-E1..E4 | Security engineering | Design only (P1/P2/P3) |
| FND-F | Agent identity spoofing or credential misuse | Identity/broker, Gateway | CTL-04, 05, 12 | PCI DSS Req. 8; ISO 27001 A.5.16/8.5; NIST CSF PR.AA; ATT&CK T1078 | High / Medium | Unique identities, approval for registration, revocation incl. deny on lookup failure, kill switch | Client registry, revocation logs, TC-F1..F2 | Identity and access team | Design only (P1/P2) |
| FND-G | Token theft, replay, confused deputy, session hijack, credential leakage | Gateway, broker, logging | CTL-04, 05, 10 | PCI DSS Req. 8/10; GDPR Art. 32; ISO 27001 A.5.17/8.5/8.15; ATT&CK T1528/T1552 | Critical / Medium | Audience binding, sender-constrained tokens (where IdP supports), token exchange, redaction | Token validation config, redaction tests TC-G5, TC-G1..G4 results | Identity and access team | Design only (P1/P2) |
| FND-H | SSRF to metadata or internal services | Egress proxy, Scanner | CTL-08, 11 | PCI DSS Req. 1; GDPR Art. 32; ISO 27001 A.8.20/8.22; ATT&CK T1552.005; DORA Art. 9 | Critical / Low-Medium | Resolve-then-pin guard, redirect re-validation, per-server egress allowlists, cloud metadata hardening | Guard config, blocked events, TC-H1..H4 | Platform security | Design only (P1/P2) |
| FND-I | Data exfiltration or cross-tenant leakage | Gateway, DLP, tenancy layer | CTL-08, 09, 10, 22 | GDPR Art. 5, 25, 32, 33/34, Ch. V; PCI DSS Req. 3/4; DORA Art. 9; ISO 27001 A.8.12; AI 600-1 data privacy; OWASP LLM02 | Critical / Medium | DLP, egress allowlists, taint rules, tenant isolation with RLS | DLP logs, egress logs, isolation tests, TC-I1..I4 | Data protection / security engineering | Design only (P2) |
| FND-J | Memory/RAG poisoning | Memory tools, Inspection | CTL-19, 09 | EU AI Act Art. 10/15 (if in scope); OWASP LLM04/08; AI 600-1 information integrity; GDPR Art. 5(1)(d) | High / Medium (target) | Attributed writes, provenance labels, partitions, rollback | Write logs, rollback records, TC-J1..J2 | Security engineering | Design only (P4) |
| FND-K | Excess autonomy, loops, budget exhaustion, unauthorised transactions | Gateway, API | CTL-12, 07 | EU AI Act Art. 14 (if in scope); OWASP LLM06/10; DORA Art. 9; ISO 27001 A.8.6 (analogous) | High / Medium | Limits, loop detection, kill switch, approvals for financial/irreversible actions | Limit config, suspension logs, TC-K1..K3 | Security engineering | Design only (P2) |
| FND-L | Supply-chain compromise | CI, admission, scanner | CTL-17, 27 | DORA Art. 28..30; GDPR Art. 28; ISO 27001 A.5.19..5.23; NIST CSF GV.SC; OWASP LLM03; PCI DSS Req. 6/12.8; EU AI Act Art. 25 (if in scope) | High / Medium | SBOM, scanning, signing and provenance, admission control, third-party intake | SBOMs, scan logs, admission logs, TC-L1..L3 | Platform security | Design only (P3/P4) |
| FND-M | Inter-agent abuse and privilege amplification | Gateway, PDP | CTL-20, 06, 12 | OWASP LLM01/06; ISO 27001 A.5.15; NIST CSF PR.AA | High / Medium (target) | Authenticated delegation, permission intersection, cycle/depth limits | Delegation logs, TC-M1..M2 | Security engineering | Design only (P4) |
| FND-N | Model extraction, denial of service, substitution | Model endpoints, Registry | CTL-21, 12 | OWASP LLM10; EU AI Act Art. 15/55 (if in scope); NIST AI RMF MANAGE; SR 11-7 inventory/versioning | Medium / Medium | Quotas, rate limits, model registry pinning, alerts | Quota logs, model registry, TC-N1..N2 | AI governance / model owner | Design only (P3/P4) |
| FND-O | Command/SQL/path injection and unsafe execution | Gateway, MCP servers | CTL-11 | PCI DSS Req. 6; ISO 27001 A.8.26/8.28/8.29; ATT&CK T1059/T1611 | High / Medium | Argument guards, schema validation, sandboxing, hardened pods | Guard rules, sandbox profiles, TC-O1..O3 | Platform security | Design only (P2/P4) |
| FND-P | MCP protocol-specific abuse (sampling, elicitation, notifications, versions) | Gateway | CTL-18 | ISO 27001 A.8.26; NIST CSF PR.PS | High / Medium | Default-deny sampling/elicitation, version allowlist, rate limits | Protocol config, TC-P1..P4 | Security engineering | Design only (P2) |
| FND-X2 | Gateway bypass through unmanaged endpoints and local servers | Discovery, network | CTL-26, 08 | ISO 27001 A.5.9; NIST CSF ID.AM; SR 11-7 complete inventory; EU AI Act Art. 26 (if in scope) | not rated / High (accepted gap) | Discovery, wrapper, egress controls, honest coverage reporting | Discovery results, coverage-gap report, TC-X2 | Security engineering | Design only (P2/P3); residual risk accepted until owners sign off |
| FND-X5 | Log injection into SIEM | Audit service | CTL-13 | ISO 27001 A.8.15; PCI DSS Req. 10; NIST CSF DE.CM | not rated / Low | Escape control characters, inert UI rendering | TC-X5 results | Security operations | Design only (P2) |
| FND-X6 | Insider approves a malicious tool or edits policy | Registry, policy store | CTL-23, 16, 13 | ISO 27001 A.5.3/8.2; SOC 2 CC6/CC8; PCI DSS Req. 7; DORA Art. 9 | not rated / Medium | SoD, dual control, source-controlled signed policy, access recertification | Approval records, policy history, TC-E4, TC-X6 | Security administration | Design only (P1/P3) |
| FND-X8 | Compromise of gateway or control plane | Platform | CTL-27, 13, 23, 15, 24 | DORA Art. 9..11; ISO 27001 A.8.x (hardening, monitoring); PCI DSS Req. 6/10/11; NIST CSF PR/DE/RS | not rated / Medium | Plane separation, no long-lived secrets, sealed break-glass, runtime detection, pen test | Pen-test reports, TC-X8 results, access reviews | Platform security | Design only (P2/P5) |

X1 (hidden text), X3 (sampling abuse), X4 (elicitation phishing) and X7 (check-to-use gap) are covered inside FND-A, FND-P and FND-B respectively; they have no separate rows.

## 6. Shared responsibility and what the platform does not address

| Topic | Platform contribution | Not covered (organisation's responsibility) |
|---|---|---|
| EU AI Act | Logging (Art. 12 support), human-oversight gates, cybersecurity measures, inventory for deployers | Risk classification of each AI system, conformity assessment, technical documentation of the AI system, fundamental-rights impact assessment where required, post-market obligations, GPAI provider obligations |
| GDPR | Security of processing support, DLP, minimisation of stored payloads (digests and redacted excerpts), tenant isolation, retention controls | Legal basis, DPIA, data-subject rights handling, records of processing, controller/processor contracts, international transfer mechanisms |
| DORA | ICT risk controls, incident evidence, third-party (MCP server) intake records, testing inputs | ICT risk management framework ownership, major-incident classification and regulatory reporting, register of information, threat-led penetration testing programme, contractual provisions with providers |
| PCI DSS | Access control, logging, segmentation support for agents touching cardholder data | Scoping decisions, QSA assessment, cardholder-data storage rules, policies |
| SR 11-7 / FFIEC | Inventory, change control, monitoring, audit trail | Model validation, outcomes analysis, model risk governance, third-party risk programme |
| ISO/NIST/SOC 2 | Evidence for security, access, logging and incident controls | Management-system establishment, internal audit, certification or attestation |

## 7. Gaps, limits and review plan

- **Unverified identifiers:** every framework reference. Priority verification list: EU AI Act article numbers, DORA articles (including technical standards), PCI DSS requirement numbers for the current version, ISO 27001:2022 Annex A numbering, NIST CSF 2.0 category IDs, SOC 2 criteria mapping, OWASP LLM and MCP lists, MITRE technique IDs.
- **Coverage not exhaustive:** other regimes relevant to a given organisation (sector or national laws, other privacy laws, other AI laws) are not mapped. Jurisdictions were not specified (PRD open question 6).
- **Phase dependence:** many controls are P2 or later; a mapping row does not mean the control exists today.
- **Matrix quality checks required before release:** legal and compliance review (FR-COMP-5); sampling of mappings by a second reviewer; confirm each "supports" statement is defensible; remove or soften any cell that cannot be justified.
- **Maintenance:** re-review when frameworks revise, when requirement IDs change, and when controls change phase. Update `Depends on` versions and run `scripts/check_docs.py`.
- **Machine-readable form:** a YAML/CSV export of Sections 3–5 is planned for `controls/` (FR-COMP-1/4) once the mapping is reviewed. Until then this document is the single source.

## 8. Change history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-11-22 | First draft; unverified references; not reviewed |

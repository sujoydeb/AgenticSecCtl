# Compliance Mapping Matrix: AgenticSecCtl

| | |
|---|---|
| Version | 0.5 (draft; **not reviewed by legal or compliance**) |
| Depends on | `Plan/functional-spec.md` v0.7, `Plan/architecture.md` v0.5, `Plan/threat-model.md` v0.5, `docs/testing/cases.md` v0.5, `docs/runbooks/operational-runbook.md` v0.3, `docs/playbooks/incident-response-playbooks.md` v0.2, `docs/tech-evaluation.md` v0.2, `controls/catalogue.md` v0.4 |
| Satisfies | FR-COMP-2..3 (mandatory/guidance/voluntary labelling, per-finding record). The control catalogue of FR-COMP-1 is in `controls/catalogue.md`. FR-COMP-5 (legal review before release) is **not yet satisfied**. |
| Review status | Review date: none. Reviewer: none. Release as an authoritative mapping is blocked until reviewed. |

## 1. Read this first

1. **A mapping is not compliance.** This matrix says which platform controls *support* which framework items by providing evidence or technical measures. It does not assert that any organisation, system or deployment complies with any law, regulation, guidance or standard. Compliance depends on the organisation's scope, role, processes, other controls and legal interpretation.
2. **Framework references are only partly verified.** Section 2 states, per framework, which identifiers were confirmed from search results (mostly secondary sources, not the official texts) and which come from background knowledge. Even confirmed identifiers must be checked against the official text and the edition in force before the matrix is relied on. Editions and numbering change (for example annexes, control sets, guidance status).
3. **Three kinds of source are kept apart** (FR-COMP-2):
   - **Mandatory law/regulation or contractual/industry mandate** (EU AI Act, GDPR, DORA, PCI DSS where in scope).
   - **Supervisory guidance** (SR 11-7, FFIEC): expected by examiners, not statute.
   - **Voluntary frameworks and standards** (NIST, ISO, SOC 2) and **community/knowledge bases** (OWASP, MITRE).
4. **Applicability is conditional.** Many mandatory provisions apply only to certain roles (provider, deployer, controller, processor, financial entity) and risk classes (for example, high-risk AI systems). The platform is a security control layer for an organisation's agents; it is not itself assumed to be a regulated AI system. Section 6 states the shared-responsibility limits.
5. **Control status is design-stage.** All controls are specified, none implemented. "Remediation status" in the findings register reflects that.

## 2. Framework register

| ID | Framework | Source type (FR-COMP-2) | Applies when | Edition to confirm | Verified |
|---|---|---|---|---|---|
| F-EUAI | EU AI Act (Regulation (EU) 2024/1689) | **Mandatory law** | Organisation is a provider/deployer/importer etc. of AI systems in scope; obligations depend on role and risk class (high-risk, GPAI) | Consolidated text and application dates | Partly: Articles 9, 12, 14, 15 confirmed (secondary sources); Articles 26 and 73 titles only |
| F-GDPR | GDPR (Regulation (EU) 2016/679) | **Mandatory law** | Processing personal data of people in the EU/EEA (or UK equivalents where relevant) | Current text | No |
| F-DORA | DORA (Regulation (EU) 2022/2554) | **Mandatory law** (EU financial entities and ICT third-party providers in scope) | Entity is in DORA scope | Regulation plus technical standards | Partly: titles of Articles 6, 9, 10, 11, 17 and 28 confirmed (secondary sources) |
| F-PCI | PCI DSS | **Contractual/industry mandate** (via card brand and acquirer agreements) | Cardholder data environment or connected systems in scope | v4.x (confirm exact version) | Partly: 12 requirements and the titles of Requirements 1 and 2 confirmed; others from background |
| F-SR117 | SR 11-7 / OCC 2011-12 Supervisory Guidance on Model Risk Management | **Supervisory guidance** | US banking organisations; models include AI/ML used in decisioning | Current guidance | No |
| F-FFIEC | FFIEC IT Examination Handbook booklets and related guidance | **Supervisory guidance** | US financial institutions | Current booklet set; confirm status of any retired tools | No |
| F-CSF | NIST Cybersecurity Framework | **Voluntary framework** (can be mandated by contract or policy) | Any | CSF 2.0 | Partly: category identifiers PR.AA, PR.DS, PR.PS, PR.IR, DE.CM, DE.AE, RS.MA, RS.AN, GV.SC, ID.AM confirmed (secondary) |
| F-AIRMF | NIST AI Risk Management Framework 1.0 | **Voluntary framework** | Any | 1.0 (confirm updates) | No |
| F-AI600 | NIST AI 600-1 Generative AI Profile | **Voluntary profile** | Organisations using generative AI | July 2024 edition (confirm) | No |
| F-ISO27001 | ISO/IEC 27001 | **Voluntary standard** (certifiable) | Organisations with or seeking certification | 2022 edition; Annex A numbering | Partly: A.5.15, A.8.12, A.8.15, A.8.28 titles confirmed (secondary) |
| F-ISO42001 | ISO/IEC 42001 AI management system | **Voluntary standard** (certifiable) | Organisations with or seeking certification | 2023 edition | No |
| F-ISO23894 | ISO/IEC 23894 AI risk management guidance | **Voluntary guidance** (not certifiable) | Any | 2023 edition | No |
| F-SOC2 | SOC 2 Trust Services Criteria | **Voluntary attestation framework** | Service organisations reporting to customers | Current TSC revision | No |
| F-OWLLM | OWASP Top 10 for LLM Applications | **Community guidance** | Any | 2025 edition (confirm) | Partly: LLM01 to LLM03 confirmed; a 2026 edition also exists, so the edition to map against must be chosen |
| F-OWMCP | OWASP MCP Top 10 | **Community guidance** | Any | 2025 list (the roadmap on the project page says beta; the sidebar says production project) | Yes for the ten entries and IDs (official project pages); content licence CC BY-NC-SA 4.0 |
| F-ATLAS | MITRE ATLAS | **Knowledge base** | Any | Current matrix and technique IDs | Partly: AML.T0051 and AML.T0010 confirmed; the ID for exfiltration via the inference API is disputed between sources (AML.T0024 or AML.T0025) |
| F-ATTCK | MITRE ATT&CK | **Knowledge base** | Any | Enterprise matrix version | No |

## 3. Controls

Control definitions (objective, how each control works, prevent/detect/respond/recover contributions, parameters, failure behaviour, false positives and negatives, bypass scenarios, residual risk, requirements, tests, evidence and metrics) are in `controls/catalogue.md`, generated from `controls/catalogue.yaml`. That catalogue is the single definition; this table only lists the IDs used by the mappings below. Types: **P** prevent, **D** detect, **R** respond, **V** recover. Owners are roles, not people.

| ID | Control | Type | Component | Owner (role) | Phase |
|---|---|---|---|---|---|
| CTL-01 | Inventory and registration of agents, servers and tools with owner, environment, criticality | P, D | Registry/API | Security engineer | P1 |
| CTL-02 | Tool scanning with reproducible scoring; approval with separation of duties and dual-control override | P, D | Scanner, Registry | Security engineer | P1 |
| CTL-03 | Definition pinning (canonical hash) and drift quarantine | P, D, R | Gateway, Registry | Security engineer | P1/P2 |
| CTL-04 | Agent identity and credential lifecycle (unique identity, rotation, revocation, deny on revocation-lookup failure) | P, R | Identity/broker | Security engineer | P1/P2 |
| CTL-05 | Authentication hardening: audience/scope validation, sender-constrained tokens, no token passthrough, session binding, server identity validation, secret redaction | P, D | Gateway, broker | Security engineer | P1/P2 |
| CTL-06 | Least-privilege authorization, deny by default, action classes, agent→server allowlists, unused-permission and escalation reporting | P, D | PDP, Gateway | Security engineer | P1/P2/P3 |
| CTL-07 | Just-in-time access and human approval for high-impact actions bound to argument hash | P | PDP, API | Approver | P2 |
| CTL-08 | SSRF protection and egress allowlisting | P, D | Egress proxy, Scanner | Security engineer | P1/P2 |
| CTL-09 | Response inspection for injection, untrusted labelling, taint rule | P, D | Gateway, Inspection | Security engineer | P2 |
| CTL-10 | Data loss prevention on requests and responses; tenant isolation | P, D | Gateway, DLP | Compliance liaison | P2 |
| CTL-11 | Argument guards, schema validation, execution sandboxing | P | Gateway, platform | Security engineer | P2/P4 |
| CTL-12 | Autonomy limits, budgets, loop detection, kill switch with different-approver resume | P, D, R | Gateway, API | Security engineer | P2 |
| CTL-13 | Tamper-evident audit: hash chain, external anchoring, reproducible decisions, deny-high-impact when audit cannot record | D | Audit service | Security on-call | P1/P2 |
| CTL-14 | Security monitoring and alerting; platform observability | D | Analytics, observability | Security on-call | P1/P2/P4 |
| CTL-15 | Incident detection, containment, evidence preservation, reporting | R, V | Incident manager | Incident commander | P2/P3/P4 |
| CTL-16 | Policy lifecycle: source control and review, signed bundles, shadow mode | P | PDP, CI | Security engineer | P1/P3 |
| CTL-17 | Supply-chain security: SBOM, vulnerability scanning, signing/provenance, third-party intake | P, D | CI, scanner, admission | Security engineer | P2/P3/P4 |
| CTL-18 | MCP lifecycle controls: version allowlist, capability limits, sampling/elicitation default-deny, roots, notifications | P | Gateway | Security engineer | P1/P2 |
| CTL-19 | Memory and RAG integrity: attributed writes, provenance labels, partitions, rollback | P, D, V | Memory tools, Inspection | Security engineer | P4 |
| CTL-20 | Inter-agent security: authenticated delegation, no privilege amplification, cycle/depth limits | P | Gateway, PDP | Security engineer | P4 |
| CTL-21 | Model registry and endpoint protection: approved model pinning, substitution detection, quotas | P, D | Registry, Gateway | Product owner | P2/P3/P4 |
| CTL-22 | Multi-tenancy, data residency and retention | P | Platform | Compliance liaison | P2/P5 |
| CTL-23 | Separation of duties, privileged and break-glass access | P, D | API, IdP | Security admin | P1/P2 |
| CTL-24 | Resilience: fail-closed behaviour, HA, backup, DR testing | P, V | Platform | Platform operator | P1/P5 |
| CTL-25 | Compliance evidence generation and framework mapping governance | D | Compliance engine | Compliance liaison | P3 |
| CTL-26 | Discovery and coverage reporting (known gaps) | D | Discovery | Security engineer | P2/P3 |
| CTL-27 | Secure development and change management for the platform | P | CI/CD, process | Delivery lead | P1 onward |
| CTL-28 | Fleet dashboard, approval workflow and notifications | P, D, R | Dashboard, API | Security engineer | P1/P2/P3 |
| CTL-29 | Data classification and labelling | P, D | Registry, Gateway, DLP | Compliance liaison | P1/P2 |
| CTL-30 | Platform key management | P, D, R | Secrets manager, KMS, CI/CD, broker | Security engineer | P2/P5 |

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
| CTL-28 Dashboard/approval workflow | Art. 14 (human oversight), Art. 26 | Art. 5(2), 24 | Art. 9, 10 | Req. 7, 10 |
| CTL-29 Data classification | Art. 10 (data governance; where applicable) | Art. 5(1)(c)(f), 25, 32 | Art. 9 | Req. 3, 7 |
| CTL-30 Key management | Art. 15 | Art. 32 | Art. 9 | Req. 3 |

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
| CTL-28 Dashboard/approval workflow | Governance reporting and effective challenge | Management; Information Security |
| CTL-29 Data classification | Data quality and confidentiality of model inputs | Information Security |
| CTL-30 Key management | — (supporting) | Information Security |

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
| CTL-28 | GV.OV, DE.AE | GOVERN; MANAGE | A.5.3, A.8.16 | 42001 performance evaluation | CC4, CC7 |
| CTL-29 | ID.AM, PR.DS | MAP; MANAGE; AI 600-1: data privacy | A.5.12, A.5.13 (classification, labelling) | 42001 data for AI systems | C1 |
| CTL-30 | PR.DS, PR.AA | MANAGE | A.8.24 (cryptography) | — | CC6 |

### 4.4 Community guidance and knowledge bases by threat

Linked to threats in `Plan/threat-model.md`. The OWASP MCP Top 10 column uses the ten entries confirmed from the official project pages (2025 list; the project's own roadmap marks it beta). The mapping of threats to entries is a judgment and is not part of the OWASP document. OWASP LLM and MITRE identifiers are only partly verified (Section 2); threats with no counterpart show a dash.

| Threat | OWASP LLM Top 10 (2025; confirm edition) | OWASP MCP Top 10 (2025) | MITRE ATLAS (technique, confirm ID) | MITRE ATT&CK (technique, confirm ID) |
|---|---|---|---|---|
| A Tool poisoning | LLM01 Prompt Injection; LLM03 Supply Chain | MCP03 Tool Poisoning | LLM prompt injection (AML.T0051) | — |
| B Rug pull/drift | LLM03 Supply Chain | MCP03 Tool Poisoning; MCP04 Software Supply Chain Attacks & Dependency Tampering | ML supply chain compromise (AML.T0010) | T1195 Supply Chain Compromise |
| C Shadowing/impersonation | LLM03 Supply Chain | MCP09 Shadow MCP Servers; MCP07 Insufficient Authentication & Authorization | — | T1036 Masquerading |
| D Response injection | LLM01 Prompt Injection; LLM05 Improper Output Handling | MCP06 Prompt Injection via Contextual Payloads; MCP10 Context Injection & Over-Sharing | LLM prompt injection (AML.T0051) | — |
| E Excessive permissions | LLM06 Excessive Agency | MCP02 Privilege Escalation via Scope Creep; MCP07 | — | T1078 Valid Accounts; T1098 Account Manipulation |
| F Agent spoofing | LLM06 Excessive Agency | MCP07 Insufficient Authentication & Authorization | — | T1078 Valid Accounts |
| G Auth attacks | LLM02 Sensitive Information Disclosure; LLM06 | MCP01 Token Mismanagement & Secret Exposure; MCP07 | — | T1528 Steal Application Access Token; T1550 Use Alternate Authentication Material; T1552 Unsecured Credentials |
| H SSRF | LLM06 Excessive Agency | No direct entry | — | T1552.005 Cloud Instance Metadata API; T1190 Exploit Public-Facing Application |
| I Exfiltration | LLM02 Sensitive Information Disclosure | MCP10 Context Injection & Over-Sharing; MCP01 | Exfiltration via ML inference API (AML.T0024; applicability partial) | T1041 Exfiltration Over C2 Channel; T1567 Exfiltration Over Web Service |
| J Memory/RAG poisoning | LLM04 Data and Model Poisoning; LLM08 Vector and Embedding Weaknesses | MCP10 Context Injection & Over-Sharing | Poison training data (AML.T0020; applicability partial) | T1565 Data Manipulation |
| K Autonomy abuse | LLM06 Excessive Agency; LLM10 Unbounded Consumption | No direct entry | — | T1499 Endpoint Denial of Service (analogous) |
| L Supply chain | LLM03 Supply Chain | MCP04 Software Supply Chain Attacks & Dependency Tampering | ML supply chain compromise (AML.T0010) | T1195 Supply Chain Compromise |
| M Inter-agent | LLM01; LLM06 | No direct entry | — | T1021 Remote Services (analogous) |
| N Model/inference | LLM10 Unbounded Consumption; LLM02 | No direct entry | Model extraction techniques (confirm IDs) | — |
| O Tool execution | LLM05 Improper Output Handling | MCP05 Command Injection & Execution | — | T1059 Command and Scripting Interpreter; T1611 Escape to Host; T1190 |
| P MCP protocol | LLM06 | MCP07; no entry for lifecycle abuse | — | — |
| X1 Hidden text and encoding | LLM01 Prompt Injection | MCP03 Tool Poisoning | — | — |
| X2 Gateway bypass / unmanaged endpoints | LLM06 Excessive Agency | MCP09 Shadow MCP Servers | — | — |
| X3 Sampling abuse | LLM10 Unbounded Consumption | No direct entry | — | — |
| X4 Elicitation phishing | LLM02 Sensitive Information Disclosure | No direct entry | — | — |
| X5 Log injection | LLM05 | MCP08 Lack of Audit and Telemetry (partial) | — | T1070 Indicator Removal (analogous) |
| X6 Insider approval | LLM06 | MCP02; MCP07 | — | T1078 Valid Accounts |
| X7 Check-to-use gap | LLM03 Supply Chain | MCP03; MCP04 | ML supply chain compromise (AML.T0010) | T1195 Supply Chain Compromise |
| X8 Gateway compromise | LLM03 | No direct entry | — | T1190; T1611; T1078 |
| X9 Agent-card spoofing | LLM06 Excessive Agency | MCP09; MCP07 | — | T1036 Masquerading |
| X10 Non-text content injection | LLM01 Prompt Injection | MCP06 | Indirect prompt injection (AML.T0051) | — |
| X11 Error-message injection | LLM05 Improper Output Handling | MCP06 | — | — |
| X12 Scanner/detector evasion or overload | LLM10 Unbounded Consumption | MCP03 (partial) | — | T1499 Endpoint Denial of Service (analogous) |
| X13 Client registration abuse | LLM06 Excessive Agency | MCP07; MCP01 | — | T1078 Valid Accounts |
| X14 Approver deception or fatigue | LLM06 Excessive Agency | MCP07 Insufficient Authentication & Authorization | — | T1078 Valid Accounts (analogous) |

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
| FND-I | Data exfiltration or cross-tenant leakage | Gateway, DLP, tenancy layer | CTL-08, 09, 10, 22, 29 | GDPR Art. 5, 25, 32, 33/34, Ch. V; PCI DSS Req. 3/4; DORA Art. 9; ISO 27001 A.8.12; AI 600-1 data privacy; OWASP LLM02 | Critical / Medium | DLP, egress allowlists, taint rules, tenant isolation with RLS | DLP logs, egress logs, isolation tests, TC-I1..I4 | Data protection / security engineering | Design only (P2) |
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
| FND-X8 | Compromise of gateway or control plane | Platform | CTL-27, 13, 23, 15, 24, 30 | DORA Art. 9..11; ISO 27001 A.8.x (hardening, monitoring); PCI DSS Req. 6/10/11; NIST CSF PR/DE/RS | not rated / Medium | Plane separation, no long-lived secrets, sealed break-glass, runtime detection, pen test | Pen-test reports, TC-X8 results, access reviews | Platform security | Design only (P2/P5) |
| FND-X9 | Forged agent card or discovery document attracts delegation or calls | Gateway, registry | CTL-20, 01 | OWASP MCP09/MCP07; ATT&CK T1036; ISO 27001 A.5.16; NIST CSF PR.AA | not rated / Medium | Treat cards as untrusted, verify against registry identity and pins, do not route unverified cards | Card verification logs, TC-X9 | Security engineering | Design only (P4) |
| FND-X10 | Instructions hidden in images, documents or audio reach the model | Gateway, inspection | CTL-09, 29 | OWASP MCP06; OWASP LLM01; ATLAS AML.T0051 | not rated / Medium | Label untrusted, limit type and size, extract and inspect, block when uninspectable in sensitive sessions | Content-handling policy, signal logs, TC-X10 | Security engineering | Design only (P2) |
| FND-X11 | Server or platform error messages carry instructions | Gateway | CTL-09 | OWASP MCP06; OWASP LLM05 | not rated / Low-Medium | Inspect server errors; fixed catalogue text for platform errors | Error-handling tests, TC-X11 | Security engineering | Design only (P2) |
| FND-X12 | Scanner or detector evasion and overload | Scanner, detectors | CTL-02, 14 | OWASP MCP03 (partial); OWASP LLM10; ATT&CK T1499 (analogous) | not rated / Medium | Caps, quotas, timeouts that never approve, evasion regression set | Regression results per rule-set version, TC-X12 | Security engineering | Design only (P2) |
| FND-X13 | Open client registration produces trusted-looking clients | Identity/broker | CTL-05, 04 | OWASP MCP07, MCP01; ATT&CK T1078; NIST CSF PR.AA | not rated / Low-Medium | Disable by default, allowlists, rate limits, owner, start unapproved | Registration policy and logs, TC-X13 | Identity and access team | Design only (P2) |
| FND-X14 | Approver deception or fatigue gets a high-impact action approved | Dashboard, approval workflow | CTL-07, 28 | OWASP MCP07; ISO 27001 A.5.3, A.8.5; NIST CSF PR.AA, GV.RR; EU AI Act Art. 14 (if in scope) | not rated / Medium | Platform-rendered arguments, step-up authentication, no bulk approval, rate and review-time alerts | Approval view tests, TC-X14, TC-Z33 | Security engineer | Design only (P2) |

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
| Model-internal risks (system-prompt leakage, memorisation, adversarial inputs, hallucination, bias) | Limits consequences through approvals, taint and egress controls | Detection or prevention of the risks themselves; model evaluation and validation, content and fairness governance (explicit exclusions in `Plan/threat-model.md` Section 4.1) |

## 7. Gaps, limits and review plan

- **Partly verified identifiers:** see Section 2 for what was confirmed; everything else is background knowledge. Priority verification list: EU AI Act article numbers, DORA articles (including technical standards), PCI DSS requirement numbers for the current version, ISO 27001:2022 Annex A numbering, NIST CSF 2.0 category IDs, SOC 2 criteria mapping, OWASP LLM and MCP lists, MITRE technique IDs.
- **Coverage not exhaustive:** other regimes relevant to a given organisation (sector or national laws, other privacy laws, other AI laws) are not mapped. Jurisdictions were not specified (PRD open question 6).
- **Phase dependence:** many controls are P2 or later; a mapping row does not mean the control exists today.
- **Matrix quality checks required before release:** legal and compliance review (FR-COMP-5); sampling of mappings by a second reviewer; confirm each "supports" statement is defensible; remove or soften any cell that cannot be justified.
- **Maintenance:** re-review when frameworks revise, when requirement IDs change, and when controls change phase. Update `Depends on` versions and run `scripts/check_docs.py`.
- **Machine-readable form:** control definitions are in `controls/catalogue.yaml`. A YAML/CSV export of the framework mappings (Sections 4–5) is still planned (FR-COMP-4) once the mapping is reviewed; until then this document is the single source for mappings.

## 8. Change history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-11-22 | First draft; unverified references; not reviewed |
| 0.2 | 2026-11-22 | Control definitions moved to `controls/catalogue.yaml`; Section 3 reduced to the ID list |
| 0.3 | 2026-11-22 | OWASP MCP entries filled from the official project; verification status per framework; threats X9..X13 and controls CTL-28, CTL-29 added; control list regenerated from the catalogue |
| 0.4 | 2026-11-22 | Owner roles aligned to the governance glossary; CTL-30 (key management) and threat X14 added; control list regenerated |
| 0.5 | 2026-11-22 | Shared-responsibility row for model-internal risks added |

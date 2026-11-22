# Product Requirements Document: AgenticSecCtl

| | |
|---|---|
| Version | 0.3 (draft for review) |
| Status | Proposal; no stakeholder has signed off |
| Depends on | `Plan/functional-spec.md` v0.5 (detailed requirements), `Plan/architecture.md` v0.4, `Plan/threat-model.md` v0.4, `docs/testing/cases.md` v0.4, `docs/tech-evaluation.md` v0.2 (mostly unverified), `docs/runbooks/operational-runbook.md` v0.3 |
| Owner | To be assigned (product); security architecture owner to be assigned |
| Scope of this document | *Why* and *for whom*, scope, priorities, release plan and success measures. Requirement-level detail lives in the functional spec and is referenced by ID, not repeated. |

## 1. Summary

AgenticSecCtl is a central security gateway and governance platform for enterprise AI agents, MCP servers and MCP tools. It lets a security team see every agent and tool in use, approve only vetted and pinned tools, control what each agent may do, inspect what flows through, stop or contain misbehaviour, and produce audit evidence. It supports multiple agents, models and clouds.

## 2. Problem

Enterprises are connecting AI agents to internal systems through MCP and similar protocols faster than security controls exist for them. The specific problems, each with a concrete failure mode:

| # | Problem | Example failure |
|---|---|---|
| P1 | No inventory: teams and individuals add agents and MCP servers on their own | Security cannot say which agents can reach customer data |
| P2 | Tool descriptions and responses are read by the model as instructions | A poisoned tool or a web page makes an agent leak data or take an action nobody approved |
| P3 | Tools can change after approval | A previously safe tool silently changes behaviour or definition |
| P4 | Permissions are coarse and long-lived | An agent holds write and delete rights it uses once a quarter |
| P5 | Credentials and sessions are easy to misuse | Stolen or over-broad tokens, confused-deputy use of server privileges |
| P6 | Evidence is scattered | Auditors and regulators ask who approved a tool and what an agent did, and the answer takes weeks |

Scanning tool descriptions alone does not solve this. Most of the risk occurs at runtime (responses, arguments, delegation, sessions), which is why the product is a gateway plus governance platform rather than a scanner.

## 3. Vision and goals

**Vision.** Every agent action on an enterprise tool is authenticated, authorized by policy, inspected and recorded, with unapproved or changed tools unable to reach agents.

**Goals** (mirrors spec Section 1; measurable targets in Section 9):
1. G1: No unapproved or modified tool is reachable by an agent.
2. G2: Every tool action is authenticated, policy-decided and recorded in a verifiable log.
3. G3: Untrusted content cannot, by itself, cause a high-impact action or data egress.
4. G4: One inventory and one evidence trail for security, risk and audit.

**Non-goals (v1).** Securing model training or hosting; replacing the enterprise IdP, SIEM, SOAR or secrets manager; endpoint protection; securing the internal logic of agents beyond what crosses the gateway; determining legal compliance; controlling unmanaged endpoints (they are discovered and reported only).

## 4. Users and their jobs

| Persona | Job to be done | What they get |
|---|---|---|
| Security engineer | Decide whether a tool or server is safe, and keep it safe | Scan findings with evidence, diffs, approval queue, quarantine |
| CISO / security leadership | Know and report AI agent exposure | Fleet dashboard, risk and compliance posture |
| Agent owner / developer | Ship an agent that can use tools without security delays | Self-service registration, clear grants, fast approvals |
| MCP server owner | Publish a server and fix findings | Scan results, drift alerts, onboarding checklist |
| Approver | Approve high-impact actions and temporary access safely | Approval tasks bound to exact arguments, with context |
| Incident responder | Contain a compromised tool or agent quickly | One-action quarantine and revoke, evidence preserved |
| Auditor / compliance officer | Produce evidence for a control or period | Immutable audit trail, evidence packs, control status |
| Platform operator | Run the platform reliably | Health, SLOs, HA, runbooks |

Roles and separation of duties are specified in spec Section 2.

## 5. Product principles
1. **Deny by default, fail closed.** Anything unknown is blocked.
2. **Deterministic enforcement.** LLM or ML detectors advise; they never alone decide a high-impact action.
3. **Server content is untrusted**, even from approved servers.
4. **Limit damage, don't rely on perfect detection.** Egress allowlists, approvals, taint rules and budgets bound what a missed attack can do.
5. **Every decision is explainable and reproducible.**
6. **Reuse before build.** Integrate mature policy, identity, DLP, SBOM, signing, telemetry and SIEM tooling; build only MCP-aware control logic.
7. **Humans approve high-impact actions**, and requesters cannot approve their own requests.

## 6. Scope and capabilities

Capabilities are grouped as in the functional spec; "FR" references identify detailed requirements.

| Capability | What the user can do | Spec | Phase |
|---|---|---|---|
| Inventory | Register and see agents, servers, tools with owner, environment, criticality | FR-INV-1..4 | P1 |
| Discovery | Find unregistered servers and agents; see coverage gaps | FR-INV-5..7 | P2/P3 |
| Tool scanning | Scan descriptions and schemas, get scored findings with evidence; block approval of critical findings | FR-SCAN-1..4, 6 | P1 |
| Integrity and drift | Pin approved definitions by hash; auto-quarantine on change; see diffs; re-approve | FR-DRIFT-1..5 | P1 |
| Authorization | Deny-by-default tool permissions by action class; agent→server allowlists | FR-AUTHZ-1..3, 8 | P1 |
| Dashboard | Fleet counts, drill-down, approval queue, drift view | FR-UI-1..3, 7 | P1 |
| Gateway protection | Authenticate agents, validate server identity, guard arguments, enforce limits | FR-AUTHN-*, FR-RT-1..3, FR-AUTO-* | P2 |
| Response and data protection | Inspect responses for injection, redact sensitive data, block exfiltration | FR-RT-4..11 | P2 |
| SSRF and egress control | Block internal/metadata access at every connection | FR-SSRF-*, FR-RT-7 | P1/P2 |
| High-impact approvals and JIT | Time-boxed access and human approval for risky actions | FR-AUTHZ-4/5 | P2 |
| Audit and evidence | Hash-chained, anchored audit; reproducible decisions; deny high-impact when audit cannot record | FR-AUD-* | P1/P2 |
| Incident response | Open incidents, quarantine, revoke, preserve evidence, report | FR-IR-* | P2/P3/P4 |
| Governance and compliance | Control catalogue, framework mapping, evidence packs; sealed break-glass administration (FR-ADM-6, P2) | FR-COMP-*, FR-POL-3/4, FR-ADM-6 | P2/P3 |
| Advanced protection | Memory/RAG integrity, behaviour analytics, supply chain, inter-agent security | FR-MEM-*, FR-BEH-2, FR-SUP-*, FR-ID-4..6 | P4 |
| Enterprise production | Multi-cloud, HA/DR, residency, enterprise integrations, red-team certification | FR-ADM-4, NFR-3/4 | P5 |

Detailed behaviours, priorities and verification methods are in `Plan/functional-spec.md` Section 4.

## 7. Key user stories (representative)

| ID | As a… | I want… | So that… | Acceptance (see spec Section 11) |
|---|---|---|---|---|
| US-1 | Security engineer | scanned findings with evidence before I approve a tool | I can decide quickly and defensibly | AC-1 |
| US-2 | Security engineer | a tool to be quarantined automatically if its definition changes | an approved tool cannot turn malicious silently | AC-2 |
| US-3 | Agent owner | to request exactly the permissions my agent needs | I get access without over-privilege | AC-3 |
| US-4 | Approver | to approve a risky call knowing the exact arguments | I am not approving a vague request | FR-AUTHZ-5 |
| US-5 | CISO | one view of agents, servers, tools, risk and incidents | I can report exposure and prioritise | AC-6 |
| US-6 | Server owner | registration to reject unsafe URLs and hostile responses | registration is not itself an attack path | AC-4, AC-8 |
| US-7 | Responder | to quarantine and revoke in one action | containment takes seconds | FR-IR-2 |
| US-8 | Auditor | to verify the audit log has not been altered | evidence is trustworthy | AC-5 |
| US-9 | Platform operator | the system to deny when its policy engine is down | an outage doesn't silently open access | AC-7 |

## 8. Release plan

Effort figures are planning estimates for a team of 2–3 engineers from the design plan; they have not been validated by engineering.

| Phase | Theme | Deliverables | Depends on | Est. effort | Exit criteria | Key risks |
|---|---|---|---|---|---|---|
| 0 | Design | Spec, architecture, threat model, test catalogue, tech evaluation (partially verified; see its verification log), PRD | — | 3–4 weeks (in progress) | Reviewed by security, architecture, compliance; open ADRs decided or scheduled | Unverified vendor claims; scope creep |
| 1 | MVP | Inventory, scanner v1, hashing and drift, basic deny-by-default authZ, audit chain, dashboard, SSRF guard | 0 | 8–10 weeks | AC-1..AC-9 pass; MVP test cases pass | Rule false positives; discovery gaps; tenancy decision |
| 2 | Runtime protection | Full gateway, authN hardening, response inspection, DLP, approvals/JIT, limits, monitoring, Redis/Kafka | 1, gateway decision (ADR-1), IdP decision (ADR-2) | 10–12 weeks | NFR-1/2 latency targets; Phase 2 test cases pass | Latency; streaming inspection; IdP capabilities |
| 3 | Governance | Fleet management, policy lifecycle, compliance mapping, evidence packs, discovery coverage | 2 | ~8 weeks | Auditor-reviewed evidence pack; mappings reviewed by legal/compliance | Mapping accuracy; framework changes |
| 4 | Advanced protection | Memory/RAG integrity, behaviour analytics, supply-chain, inter-agent security, automated IR | 3 | ~12 weeks | Red-team scenarios detected/contained | ML false positives; agent protocol churn |
| 5 | Enterprise production | Multi-cloud, HA/DR, residency, SIEM/SOAR integrations, continuous validation, red-team certification | 4 | 12+ weeks | HA/DR drills, external penetration test | Operational maturity; residency rules |

Phase gates are decision points: a phase starts only when its dependent decisions (ADR-1..7) are closed or explicitly deferred with an owner.

## 9. Success metrics

| Metric | Target | Measured how | Phase to baseline |
|---|---|---|---|
| Managed agent tool calls passing through the gateway | 100% in managed environments | Gateway vs egress/discovery comparison | P2 |
| Time from definition change to quarantine | ≤ one list cycle (≤ 60 s fallback) | TC-B1, TC-B4 | P1/P2 |
| Detection of seeded poisoned tools | ≥ 95% recall, ≥ 90% precision on benchmark corpus | Labelled corpus run (corpus to be built) | P1 |
| Unapproved high-impact actions in red-team tests | 0 | Red-team results | P2+ |
| Findings with an owner and remediation status | 100% | Dashboard query | P3 |
| Added gateway latency, deterministic path | p95 ≤ 25 ms, p99 ≤ 60 ms at 1,000 req/s per instance | Load test per NFR-1 | P2 |
| Median time to approve a clean tool (adoption proxy) | To be set after pilot | Workflow timestamps | P1 pilot |
| False-block rate on benign traffic (shadow mode) | ≤ 0.5% of calls | Shadow-mode logs | P2 |

All targets are proposals; none has been measured.

## 10. Dependencies and assumptions
- An OIDC identity provider; support for sender-constrained tokens and token exchange is unverified (ADR-2, `docs/tech-evaluation.md`).
- Kubernetes environment for deployment; Docker Compose for development.
- Customer decisions needed: SIEM target, approval channel (dashboard only or ServiceNow/Slack), single vs multi-tenant, applicable jurisdictions and regulators.
- MCP specification evolves; compatibility is tracked per revision.
- Third-party product capabilities are unverified until the verification checklist in the technology evaluation is complete.
- Legal review is required for compliance mappings and for licences of any bundled third-party components or content (for example, some framework documents carry non-commercial licences).

## 11. Risks

| Risk | Impact | Mitigation | Owner (to assign) |
|---|---|---|---|
| Attackers bypass probabilistic detection | Data loss or unapproved action | Blast-radius controls, approvals, egress allowlists, red-team regression | Security architecture |
| Gateway becomes a high-value target and single point of failure | Wide compromise or outage | Plane separation, no long-lived secrets, HA, dedicated penetration test, tested fail-closed behaviour | Platform |
| Unmanaged endpoints and local servers bypass the gateway | Coverage gap | Discovery, wrapper, egress controls, honest coverage reporting | Product |
| Detector false positives slow developers | Adoption failure, shadow IT | Shadow mode, quality budgets, clear override paths with dual control | Product |
| Approvers rubber-stamp | Weak assurance | Dual control for critical findings, recertification, unused-permission reports | Security |
| IdP lacks required features | Weaker token security | Documented fallback (short-lived tokens, mTLS), early spike | Identity |
| Regulatory mapping read as a compliance claim | Legal exposure | Evidence-support wording, legal review, mandatory/guidance/voluntary labels | Compliance |
| Spec and tool churn | Rework | Version-pinned compatibility matrix, scheduled re-verification | Architecture |
| Fail-closed behaviour causes business outage | Lost productivity | HA, tested degradation, tenant allowlist for low-risk read-only tools | Platform |

## 12. Open questions
1. Build the gateway or extend an open-source MCP gateway? (ADR-1; spike S1)
2. Which production IdP, and does it support DPoP/mTLS binding and token exchange? (ADR-2; spike S2)
3. Approval channel for the MVP: dashboard only, or integrate ServiceNow/Slack? (ADR-3)
4. Single-tenant per deployment or shared multi-tenant first? (ADR-4; needed before schema freeze)
5. How should local stdio servers be handled? (ADR-5)
6. Which jurisdictions and regulators define the first compliance matrix?
7. Which SIEM and SOAR products must be supported at launch?
8. Pilot scope: which business unit, how many agents and servers, and which environments?
9. Who owns the benchmark corpus for detector quality and how is it maintained?

## 13. Out-of-scope for this PRD
Pricing, packaging and commercial go-to-market are not covered; the document assumes an internally built or customer-deployed enterprise platform. Market sizing and competitive claims are deliberately omitted because they were not verified.

## 14. Traceability
- Requirements: `Plan/functional-spec.md` (FR/NFR/AC IDs).
- Threats and controls: `Plan/threat-model.md`.
- Components and sequences: `Plan/architecture.md`.
- Verification: `docs/testing/cases.md` (99 TC-* cases; MVP set in its Section 20).
- Operations: `docs/runbooks/operational-runbook.md` (design-stage draft).
- Audit event vocabulary: `Plan/architecture.md` Section 4.8.
- Technology choices and unverified claims: `docs/tech-evaluation.md`.

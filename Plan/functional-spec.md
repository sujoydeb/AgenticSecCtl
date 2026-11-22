# Functional Specification: AgenticSecCtl
**Enterprise Agentic AI & MCP Security Gateway and Governance Platform**

| | |
|---|---|
| Version | 0.7 (draft for review) |
| Supersedes | 0.6 |
| Stack decisions | Python/FastAPI, Postgres, OPA, React, cloud-neutral Kubernetes; Redis/Kafka from Phase 2 |
| Conventions | "shall" = mandatory requirement. **[VERIFY]** = vendor, product or protocol claim not yet checked against current documentation. |

## 0. Change log

### v0.6 → v0.7 (remaining Medium gaps)

| # | Change | Where |
|---|---|---|
| 1 | Lifecycle requirements updated from the rest of the 2026-07-28 specification: no initialize handshake, `server/discover`, per-request version and capabilities, `subscriptions/listen` notifications, client metadata documents fetched through the SSRF guard (gap E3) | FR-MCP-2, FR-MCP-8, FR-SSRF-1 |

### v0.5 → v0.6 (closure of Low review gaps)

| # | Change | Where |
|---|---|---|
| 1 | Governance of additional high-impact action classes and the critical resource tag: FR-AUTHZ-12 and a glossary entry (gap D7) | Section 4.6, glossary |
| 2 | Test case TC-Z34 linked; AC-13 and the traceability row extended | Sections 5 and 11 |

### v0.4 → v0.5 (closure of Medium review gaps)

Changes made to close Medium findings in `docs/reviewgap.md`. New requirements are marked *added in v0.5; review required*.

| # | Change | Where |
|---|---|---|
| 1 | MCP lifecycle rows get requirement IDs FR-MCP-1..12 and are updated from the 2026-07-28 specification text: deprecated sampling and roots, no protocol-level sessions, Origin validation, elicitation limits (gaps B6, E3) | Section 4.12 |
| 2 | Acceptance criteria AC-10..AC-24 for phases 2 to 5 (gap B5) | Section 11 |
| 3 | Emergency policy defined: FR-AUTO-6 (gap D2) | Section 4.8, glossary |
| 4 | Legal hold and raw-evidence access: FR-ADM-7, FR-ADM-8 (gap D3) | Section 4.18 |
| 5 | Retention default marked as a placeholder pending legal input (gap D5) | NFR-6 |
| 6 | Key management: FR-KEY-1..6 (gap H3) | Section 4.23 |
| 7 | Approval content, step-up authentication and fatigue limits: FR-AUTHZ-9..11; new threat X14 (gap H4) | Sections 4.6, 5 |
| 8 | Test-case links extended for thin threats and new requirements (gap B4) | Section 5 |

### v0.3 → v0.4 (closure of High review gaps)

Changes made to close the High findings in `docs/reviewgap.md`. New requirements are marked *added in v0.4; review required*. Decisions are recorded as **proposed, pending approval**.

| # | Change | Where |
|---|---|---|
| 1 | Data classification model added: FR-DATA-1..4 (gap D1) | Section 4.22 |
| 2 | Threats X9..X13 get requirements: FR-ID-8, FR-RT-12, FR-RT-13, FR-SCAN-10, FR-AUTHN-7 (gap H1) | Sections 4.2, 4.4, 4.5, 4.7 |
| 3 | FR-SUP-1 retagged to P2 for the platform's own images; new FR-SUP-4 keeps the P4 server-fleet requirement (gap C1) | Section 4.11 |
| 4 | Threat traceability extended to X13 with test cases for every threat; phase-conflicting test cases corrected in the test catalogue (gaps B2, B3, C1) | Section 5 |
| 5 | AC-5 and AC-6 mapped to additional test cases | Section 11 |
| 6 | Assumptions A5 and A6 added from verification of the MCP specification revision 2026-07-28 (gap E3, partly) | Section 3 |
| 7 | Open decisions get proposed resolutions pending approval (ADR-1, 2, 3, 4, 6) (gap F1) | Section 12 |

### v0.2 → v0.3 (document synchronisation)

Changes made so the spec agrees with the later documents (architecture, threat model, test catalogue, runbook, tech evaluation). Requirements marked *added from runbook* are new and need review by the owners named in Section 12.

| # | Change | Where |
|---|---|---|
| 1 | Architecture document now exists; reference added | Section 3 |
| 2 | Five requirements promoted from the operational runbook (*added from runbook*): FR-ID-7, FR-AUTO-5, FR-SCAN-9, FR-AUD-7, FR-ADM-6 | Sections 4.2, 4.4, 4.8, 4.14, 4.18 |
| 3 | OWASP MCP Top 10 existence verified (identifiers still pending); licence caveat recorded | Section 4.19 |
| 4 | Test-case column added to the threat traceability table; closing note replaced | Section 5 |
| 5 | AC-9 mapped to new test case TC-G5; acceptance criteria mapped to test cases | Section 11 |

### v0.1 → v0.2

Review of v0.1 found the following. Each is fixed in v0.2.

| # | Finding in v0.1 | Resolution in v0.2 |
|---|---|---|
| 1 | `jti` replay check on access tokens would break legitimate reuse of bearer tokens | FR-AUTHN-2: sender-constrained tokens (DPoP or mTLS) + short TTL + revocation; `jti` only for one-time artifacts |
| 2 | SSRF checked only at registration (DNS rebinding / redirect TOCTOU) | FR-SSRF-1..4: check at every outbound connection, resolve-then-pin, redirect re-validation |
| 3 | Tool import from an untrusted URL treated as safe | FR-SCAN-6: hardened importer (timeouts, size/depth caps, no redirects, sandboxed worker) |
| 4 | Phase tags contradicted roadmap (JIT, IR, discovery) | Phases re-aligned; basic discovery moved to Phase 2 |
| 5 | Audit hash chain implied tamper-proof | FR-AUD-4: external anchoring; limits stated |
| 6 | NFR targets had no measurement method | Section 9 adds method per target |
| 7 | Threats A–P not traceable; J, K, L, M, N, O had little or no coverage | Section 5 traceability matrix; new requirement groups |
| 8 | MCP lifecycle covered by one bullet | Section 4.12 lifecycle table |
| 9 | No RBAC, separation of duties, tenancy, retention, error model, glossary, metrics | Sections 1, 2, 4.21, 8 |
| 10 | Undefined severity, risk score, "excessive", "high-impact" | Sections 4.2, 4.6 |
| 11 | Acceptance criteria covered 7 items, no per-FR verification | Every FR has a verification method; Section 11 expanded |
| 12 | Compliance section could be read as claiming compliance | Section 4.19 states evidence-support only; per-framework status table |

---

## 1. Purpose, goals and scope

**Purpose.** Give an enterprise one control point to discover, register, scan, authorize, monitor, contain and audit AI agents, MCP servers and MCP tools across multiple agents, models and clouds.

**Goals**
- G1: No unapproved or modified tool is reachable by an agent.
- G2: Every agent action on a tool is authenticated, authorized by policy and recorded in a verifiable log.
- G3: Untrusted content (tool descriptions, tool responses, retrieved data) cannot, on its own, cause a high-impact action or data egress.
- G4: Security, risk and audit teams see one inventory and one evidence trail.

**Success metrics (to be baselined in Phase 2)**

| Metric | Target |
|---|---|
| Share of registered-agent tool calls passing through the gateway | 100% in managed environments |
| Time from tool-definition change to quarantine | ≤ one `tools/list` cycle (≤ 60 s polling fallback) |
| Seeded poisoned tools detected by deterministic rules (corpus defined in Section 10) | ≥ 95% recall, ≥ 90% precision on the benchmark corpus |
| Unapproved high-impact actions executed in red-team tests | 0 |
| Findings with owner and remediation status | 100% |

**Out of scope (v1).** Training/hosting security of models; endpoint EDR; replacing the enterprise IdP, SIEM, SOAR or secrets manager; legal determination of compliance; securing agents' own application logic beyond what crosses the gateway; unmanaged endpoints (reduced to discovery and reporting only).

**Glossary**
- **PEP / PDP**: policy enforcement point (gateway) / policy decision point (OPA).
- **Tool definition**: name, description, input schema, output schema, annotations of an MCP tool.
- **Quarantine**: tool/server/agent remains registered but is blocked from use.
- **Taint**: label marking content from an untrusted origin.
- **High-impact action**: see FR-AUTHZ-5.
- **JIT grant**: time-boxed permission issued on request and approval.
- **Critical resource**: a resource its owner has tagged critical in the registry, with the tag confirmed by the approver at approval (FR-AUTHZ-12); writes and executes on critical resources are high-impact (FR-AUTHZ-5).
- **Emergency policy**: a tenant-approved, pre-defined policy that lets named people relax only the different-approver rule for resuming a suspended agent or tenant, for a limited time, with high-severity audit; see FR-AUTO-6.

---

## 2. Personas, roles and separation of duties

| Role | Can | Cannot |
|---|---|---|
| Viewer | Read dashboards | Change anything |
| Agent owner | Register agents, request grants | Approve own requests |
| Server owner | Register servers, remediate findings | Approve own server's tools |
| Security engineer | Run scans, approve/reject tools, quarantine | Approve own registrations; override critical findings alone |
| Approver | Approve JIT grants and high-impact calls | Approve requests they raised |
| Security admin | Manage policy, integrations, roles | Modify or delete audit records |
| Auditor | Read all evidence, export | Modify anything |
| Incident responder | Contain, revoke, preserve evidence | Delete evidence |
| Platform operator | Operate infrastructure | Read raw evidence vault content |

Separation-of-duties rules (SoD):
- SoD-1: Requester and approver shall be different identities for tool approval, JIT grants and high-impact calls.
- SoD-2: Overriding a critical finding shall need two distinct approvers (dual control) and a written justification with expiry.
- SoD-3: No role shall be able to alter or delete audit events through application interfaces.

---

## 3. Context and assumptions

Trust zones, component responsibilities and the interceptor pipeline are defined in `architecture.md` (v0.3) and analysed in `threat-model.md` (v0.3). Assumptions:
- A1: An OIDC identity provider is available (Keycloak for development; production IdP undecided).
- A2: MCP servers and all content they return are untrusted until registered and pinned; even then, response content stays untrusted.
- A3: MVP gateway covers Streamable HTTP. Local stdio servers need a wrapper (Phase 2).
- A4: Detectors are probabilistic. Enforcement of high-impact actions never depends on a single detector or on an LLM classifier.
- A5: The reference MCP specification revision is 2026-07-28; the authorization, transport, sampling, elicitation and roots pages were read (see `docs/mcp-compatibility.md`). In that revision authorization is optional, HTTP transports SHOULD follow the OAuth 2.1 based authorization specification (resource indicators per RFC 8707, protected resource metadata per RFC 9728), dynamic client registration is deprecated in favour of client ID metadata documents, there are no protocol-level sessions, and sampling and roots are deprecated.
- A6: Because server-side authorization is optional and stdio transports take credentials from the environment, the platform enforces authentication and authorization at the gateway and never relies on a server doing so.

---

## 4. Functional requirements

Priority: **M** must, **S** should, **C** could. Phase: **P1** MVP, **P2** runtime protection, **P3** governance, **P4** advanced threat protection, **P5** enterprise production. "Threats" refer to Section 5 (A–P plus added vectors X1–X13). "Verify" is the test method: UT unit, IT integration, E2E end-to-end, RT red-team, PT penetration, FZ fuzz, DM demonstration/inspection.

### 4.1 Inventory and discovery (FR-INV)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-INV-1 | The system shall maintain records of agents, MCP servers and tools with owner, environment, business criticality and risk class. | M | P1 | C, F | IT |
| FR-INV-2 | Each server shall have a unique ID and namespace; tools shall be addressed as `namespace__tool`. | M | P1 | C | UT, IT |
| FR-INV-3 | The system shall flag tools with identical names across servers and shall never route an ambiguous name implicitly. | M | P1 | C | IT |
| FR-INV-4 | Servers and agents not registered shall be denied by the gateway. | M | P1 | C, F | E2E |
| FR-INV-5 | The system shall discover candidate assets from Kubernetes, MCP client config files, egress logs and cloud inventories and list them as `unregistered`. | S | P2 | X2 | IT, DM |
| FR-INV-6 | The system shall store a relationship graph Agent → Model → MCP Server → Tool → Data Source → Enterprise System. | S | P3 | — | DM |
| FR-INV-7 | The system shall report known coverage gaps (unmanaged endpoints, direct connectors) in the dashboard. | S | P3 | X2 | DM |

### 4.2 Tool scanning (FR-SCAN)

Severity taxonomy: **Critical** (direct instruction to exfiltrate, override system rules, or request credentials; or hidden characters carrying instructions), **High** (external URL/IP in description, free-form command/path/URL parameters without constraints, tool-chaining instructions), **Medium** (overly broad schema, encoded blobs, annotation inconsistent with schema), **Low** (stylistic or informational), **Info**.

Risk score (reproducible): `score = min(100, Σ rule_weight × confidence)` with weights Critical 40, High 20, Medium 8, Low 2, confidence 0–1 fixed per rule; rule set and weights are versioned and stored with each scan. A scan record shall include rule-set version so results can be reproduced.

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-SCAN-1 | The scanner shall analyze name, description, schemas and annotations using deterministic rules for: override/hidden instructions, invisible and bidirectional Unicode, URLs/IPs, credential or secret requests, instructions to call other tools, encoded blobs, schema anomalies. | M | P1 | A, X1 | UT, RT |
| FR-SCAN-2 | Each finding shall carry rule ID, severity, location, evidence excerpt and confidence; each scan shall produce a risk score per the formula above. | M | P1 | A | UT |
| FR-SCAN-3 | An optional LLM classifier shall be pluggable and advisory; it may raise severity but shall never lower a deterministic severity or approve a tool. | M | P1 | A | UT |
| FR-SCAN-4 | A tool with a Critical finding shall not be approvable except through SoD-2 override. | M | P1 | A | IT |
| FR-SCAN-5 | The system shall scan server artifacts (packages, images, dependencies) for known vulnerabilities, typosquatted names, missing signatures/provenance, and produce an SBOM. [VERIFY tooling] | S | P4 | L | IT |
| FR-SCAN-6 | Tool import from a server URL shall run in an isolated worker with connection/read timeouts, a response size cap, JSON depth/count limits, no redirects by default, and SSRF controls (Section 4.10). | M | P1 | A, H | UT, FZ |
| FR-SCAN-7 | Scans shall re-run on a schedule and on any drift; findings shall be deduplicated and tracked by status (open, accepted with expiry, fixed). | S | P3 | A, B | IT |
| FR-SCAN-8 | Scan inputs sent to an external LLM service shall require explicit per-tenant opt-in; a self-hosted option shall be supported. | S | P2 | I | DM |
| FR-SCAN-9 | When a rule set is updated, approved tools shall be re-scanned: a Critical finding on an approved tool shall quarantine it and notify its owner and approvers; lower severities shall create review items without quarantine. *(added from runbook; review required)* | S | P3 | A, B | IT |
| FR-SCAN-10 | The scanner and detectors shall protect their own availability and integrity: input size and complexity caps, per-tenant queue quotas, timeouts that result in not approved (never in automatic approval), and a regression set of evasion samples that runs on every rule-set or model update. *(added in v0.4; review required)* | S | P2 | A, X12 | UT, FZ |

### 4.3 Definition integrity and drift (FR-DRIFT)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-DRIFT-1 | On approval the system shall store the canonical definition (RFC 8785 JSON canonicalization, Unicode NFC) and SHA-256 over server ID, name, description, input schema, output schema and annotations. Approved versions shall be immutable. | M | P1 | B | UT, IT |
| FR-DRIFT-2 | The gateway shall recompute and compare on every `tools/list`, on `notifications/tools/list_changed`, and on a scheduled poll. A mismatch shall quarantine the tool, raise a finding and notify approvers. | M | P1 | B | E2E |
| FR-DRIFT-3 | A quarantined tool shall be removed from `tools/list` results and `tools/call` shall be denied. | M | P1 | B | E2E |
| FR-DRIFT-4 | The UI shall show a field-level diff between approved and current definitions. | M | P1 | B | DM |
| FR-DRIFT-5 | Re-approval shall create a new immutable version; the full version history shall be retained. | M | P1 | B | IT |
| FR-DRIFT-6 | The system shall baseline response shape, size and latency per tool and flag deviations. Definition hashing does not prove behavior is unchanged; this control is a compensating one. | S | P4 | B | RT |
| FR-DRIFT-7 | Hash checks shall be performed against the approved record at call time, not only at list time, to remove the check-to-use gap (cached definition ≤ configurable TTL, default 60 s). | M | P2 | B | IT, race test |

### 4.4 Agent identity (FR-ID)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-ID-1 | Each agent shall have a unique identity and OAuth client; shared credentials shall not be permitted. | M | P1 | F | IT |
| FR-ID-2 | Agent registration shall require an owner and an approval by someone other than the requester (SoD-1). | M | P1 | F | IT |
| FR-ID-3 | The system shall support credential rotation, immediate revocation and a revocation list consulted by the gateway. | S | P2 | F, G | E2E |
| FR-ID-4 | Agent-to-agent calls shall be authenticated and authorized through the gateway; each call shall carry the delegation chain. | S | P4 | F, M | IT, RT |
| FR-ID-5 | The system shall detect and block circular delegation and enforce a maximum delegation depth (default 3). | S | P4 | K, M | UT, RT |
| FR-ID-6 | A sub-agent shall never receive more permission than the delegating agent holds for the same request (no privilege amplification). | M | P4 | M | UT, RT |
| FR-ID-7 | If the revocation list or revocation service cannot be consulted, the gateway shall deny the request rather than skip the check. *(added from runbook; review required)* | M | P2 | F, G | IT |
| FR-ID-8 | Agent cards and discovery documents shall be treated as untrusted input: capabilities, endpoints and keys they advertise shall be verified against registry identity and pins before use, and unverified cards shall not be routed. *(added in v0.4; review required)* | S | P4 | F, M, X9 | IT, RT |

### 4.5 Authentication (FR-AUTHN)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-AUTHN-1 | The gateway shall validate token signature, issuer, expiry, audience (the gateway/resource identifier) and scope on every request. [VERIFY against current MCP authorization spec] | M | P1 | G | UT, IT |
| FR-AUTHN-2 | Access tokens shall be sender-constrained (DPoP or mTLS binding) where the IdP supports it, with short lifetime (default ≤ 10 min) and revocation. One-time artifacts (approval tokens, exchange requests) shall use `jti` single-use. [VERIFY IdP support] | S | P2 | G | IT, PT |
| FR-AUTHN-3 | The gateway shall not pass client tokens through to MCP servers. It shall obtain audience-bound upstream tokens by token exchange or use server-specific credentials from the secrets broker. [VERIFY] | M | P2 | G | IT, PT |
| FR-AUTHN-4 | Sessions shall be bound to the authenticated client; use of a session ID by a different client or network identity shall be rejected and alerted. | M | P2 | G | PT |
| FR-AUTHN-5 | Server identity shall be validated (TLS chain, pinned certificate or JWKS per registry entry); failure shall deny and raise an alert. | M | P2 | C | IT |
| FR-AUTHN-6 | Secrets and tokens shall never appear in logs, findings or UI; this shall be enforced by log redaction tests. | M | P1 | G, I | UT |
| FR-AUTHN-7 | Client registration with the platform's authorization components shall not be open: dynamic client registration and client-metadata-document registration shall be disabled unless enabled per tenant with approval, allowlisted redirect URIs or metadata hosts, rate limits and an assigned owner; newly registered clients shall start unapproved. *(added in v0.4; review required)* | M | P2 | G, F, X13 | IT, PT |

### 4.6 Authorization (FR-AUTHZ)

Action classes: **read**, **write**, **execute**, **delete**. Mapping from tool to action class is set by the tool owner and approver at registration and stored in the registry. Tool annotations shall not be used as authorization inputs.

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-AUTHZ-1 | Every call shall be decided by the PDP on (agent, tool, action class, resource, arguments digest, context). Default shall be deny. | M | P1 | E | UT, IT |
| FR-AUTHZ-2 | An agent→server allowlist shall be enforced. | M | P1 | C, E | IT |
| FR-AUTHZ-3 | Permissions shall be per tool and action class with optional resource patterns. | M | P1 | E | UT |
| FR-AUTHZ-4 | JIT grants shall have a mandatory TTL, requester, approver (SoD-1) and reason, and shall expire automatically. | S | P2 | E | IT |
| FR-AUTHZ-5 | High-impact actions shall require human approval bound to the hash of exact arguments. High-impact = any delete; any write/execute on a resource tagged critical; any outbound send of data classified confidential or above; any financial transaction; any action taken after untrusted content from a sensitive-data read in the same session (taint rule). Customers may add classes. | M | P2 | E, K | E2E, RT |
| FR-AUTHZ-6 | The system shall report permissions unused for N days (default 30) and permissions broader than observed use. | S | P3 | E | IT |
| FR-AUTHZ-7 | The system shall alert on permission changes outside an approved change record (escalation). | S | P3 | E | IT |
| FR-AUTHZ-8 | If the PDP or its policy bundle is unavailable the gateway shall deny (fail-closed). A tenant may allowlist specific read-only low-risk tools for fail-open with audit; every such decision shall be flagged in the audit log. | M | P1 | E | E2E |
| FR-AUTHZ-9 | An approval request shall show the approver the requester, tool, action class, resource, classification, current taint state and the exact arguments or a platform-generated redacted rendering of them with their hash; any text supplied by the agent shall be shown only in a labelled untrusted area. *(added in v0.5; review required)* | M | P2 | E, X14 | IT, DM |
| FR-AUTHZ-10 | High-impact approvals and Critical-finding overrides shall require step-up authentication (fresh multi-factor authentication within a configured window). *(added in v0.5; review required)* | M | P2 | E, X14 | IT |
| FR-AUTHZ-11 | Bulk approval of high-impact actions shall be disabled; approval rates and very short review times shall be monitored and alerted, and a configurable limit of pending high-impact approvals per approver shall apply. *(added in v0.5; review required)* | S | P2 | E, X14 | IT, RT |
| FR-AUTHZ-12 | Tenants may add high-impact action classes and critical resource tags only through the audited management API by the security admin role, with a recorded reason and an approver other than the requester; new classes and tags shall run in shadow mode before enforcement; removing a class or tag needs the same approvals; the built-in classes of FR-AUTHZ-5 cannot be removed. *(added in v0.6; review required)* | S | P2 | E, X6 | IT |

### 4.7 Runtime inspection and data protection (FR-RT)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-RT-1 | `tools/list` responses shall be filtered to approved, non-quarantined tools the caller is permitted to use. | M | P1 | A, B, E | E2E |
| FR-RT-2 | Arguments shall be validated against the approved input schema; unknown fields rejected. | M | P2 | O | UT, FZ |
| FR-RT-3 | Argument guards shall reject path traversal, command and SQL metacharacters in parameters declared as path/command/query, and URL parameters failing SSRF controls. | M | P2 | O, H | UT, PT |
| FR-RT-4 | Responses shall be inspected for injection signals in text, HTML, JSON and markdown (including comments, hidden elements, markdown image/link exfiltration patterns); outcomes: allow-with-label, redact, block, quarantine-tool, by policy. | M | P2 | D | UT, RT |
| FR-RT-5 | All tool output shall be labelled untrusted and delivered in a structure that separates it from system/developer instructions; a tool response shall never modify system-level instructions. | M | P2 | D | RT |
| FR-RT-6 | Requests and responses shall be inspected for PII, financial identifiers (Luhn-validated), secrets/API keys, source-code markers and tenant data tags; actions: redact, block, alert. | M | P2 | I | UT, RT |
| FR-RT-7 | Outbound destinations of tools shall be limited to a per-server egress allowlist enforced outside the gateway process (NetworkPolicy/egress proxy). | M | P2 | I, H | PT |
| FR-RT-8 | Cross-tenant isolation: every request, cache entry, log and evidence record shall carry a tenant ID and be unreachable from other tenants; tested with negative cases. | M | P2 | I | PT |
| FR-RT-9 | Taint rule: after an untrusted read of sensitive data, the session shall be blocked from write/execute/external-send tools until approved (the "private data + untrusted content + external communication" combination). | M | P2 | D, I, K | RT |
| FR-RT-10 | Response size, time and rate limits shall apply per tool and per session. | M | P2 | K, N | DoS test |
| FR-RT-11 | Inspection detectors shall emit signals with confidence; no LLM classifier shall be the only control for any high-impact decision. | M | P2 | D | DM |
| FR-RT-12 | Non-text content in tool responses (images, documents, audio) shall be labelled untrusted and limited by type and size; it shall reach the model only if policy allows, text extracted from it shall pass the same inspection as text responses (FR-RT-4), and content that cannot be inspected shall be blocked for sessions that hold sensitive data. *(added in v0.4; review required)* | M | P2 | D, X10 | UT, RT |
| FR-RT-13 | Error payloads returned by servers shall be treated as untrusted responses and inspected like any response; errors generated by the platform towards agents shall use fixed catalogue text and shall not echo untrusted content. *(added in v0.4; review required)* | M | P2 | D, X11 | UT, RT |

### 4.8 Agent autonomy controls (FR-AUTO)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-AUTO-1 | Per-agent and per-session limits shall apply to tool calls, distinct tools, depth of delegation, wall-clock time and cost/tokens. | M | P2 | K | E2E |
| FR-AUTO-2 | The system shall detect repeating call sequences (loops) and suspend the session. | S | P2 | K | UT |
| FR-AUTO-3 | Autonomous financial or irreversible transactions shall require approval unless a policy explicitly permits a bounded amount and counterparty. | M | P2 | K | E2E |
| FR-AUTO-4 | A kill switch shall suspend an agent or all agents of a tenant within 5 s of command. | M | P2 | K | E2E |
| FR-AUTO-5 | Resuming a suspended agent or tenant shall require an approver other than the person who suspended it (SoD-1), unless an emergency policy (FR-AUTO-6) applies; both actions shall be audited. *(added from runbook; review required)* | M | P2 | K | E2E |
| FR-AUTO-6 | An emergency policy shall name the people who may declare an emergency, state that it may relax only the different-approver rule of FR-AUTO-5 (never authentication, SSRF, audit, high-impact approval or classification rules), set a maximum duration, and notify security and the tenant owner; each use shall raise a high-severity audit event and be reviewed within one business day. *(added in v0.5; review required)* | S | P2 | K, X6 | IT, E2E |

### 4.9 Memory, retrieval and model controls (FR-MEM, FR-MOD)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-MEM-1 | Writes to agent memory and vector stores through managed tools shall be attributed (agent, source, session) and authorized; writes derived from untrusted content shall be labelled. | S | P4 | J | IT |
| FR-MEM-2 | Content retrieved from memory/RAG shall be inspected as in FR-RT-4 and carry its provenance label. | S | P4 | J | RT |
| FR-MEM-3 | Memory partitions shall be per agent/tenant; cross-agent reads require explicit grant. | S | P4 | J, M | PT |
| FR-MEM-4 | The system shall support bulk rollback of memory entries by source or time window. | C | P4 | J | DM |
| FR-MOD-1 | The model registry shall record approved model identifier/version and endpoint per agent; substitution shall be detected and alerted. | S | P3 | N | IT |
| FR-MOD-2 | Model endpoints reached through the platform shall require authentication, rate limits and quotas to reduce extraction and denial of service. | S | P4 | N | DoS test |
| FR-MOD-3 | The platform shall not itself store model weights or training data (out of scope); model artifact provenance checks shall be reported when supplied. | C | P4 | L, N | DM |

### 4.10 SSRF protection (FR-SSRF)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-SSRF-1 | Every outbound connection initiated by the platform (registration, import, discovery, health check, proxying, fetching client metadata documents) shall pass the SSRF guard. | M | P1 | H | UT, PT |
| FR-SSRF-2 | The guard shall resolve DNS, validate every returned address against the blocklist (loopback, link-local including 169.254.169.254, RFC 1918/ULA, multicast, unspecified, IPv4-mapped IPv6, metadata hostnames) and connect to the validated IP (resolve-then-pin) to defeat rebinding. | M | P1 | H | UT, PT |
| FR-SSRF-3 | Redirects shall be disabled by default; if enabled, each hop shall be re-validated, max 3. | M | P1 | H | UT |
| FR-SSRF-4 | Alternate encodings (decimal, octal, hex, IPv6 forms, userinfo tricks, unicode hosts) shall be normalized before checks. | M | P1 | H | FZ |
| FR-SSRF-5 | Exceptions (internal servers) shall be explicit per-server allowlist entries with owner approval and expiry. | M | P1 | H | IT |

### 4.11 Tool execution and supply chain (FR-EXEC, FR-SUP)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-EXEC-1 | Server-owner guidance and admission policy shall require platform-hosted MCP servers to run non-root, read-only filesystem, no privileged capabilities, resource limits, and a sandboxed runtime for tools executing code. [VERIFY runtime availability per cloud] | S | P4 | O | DM, PT |
| FR-EXEC-2 | File upload/download tools shall enforce type, size and malware-scan checks. | S | P4 | O | IT |
| FR-SUP-1 | The platform's own images shall be signed, referenced by digest and verified at admission; unsigned, tag-only or non-compliant workloads shall be rejected in platform namespaces. *(retagged P4 to P2 in v0.4: the CI/CD and deployment designs require it)* | M | P2 | L | IT |
| FR-SUP-2 | Server package names shall be checked for typosquatting against registry allowlists and known popular names. | S | P4 | L | UT |
| FR-SUP-3 | Third-party servers shall go through a documented intake (SBOM, owner, licence, vulnerability status) before approval. | S | P3 | L | DM |
| FR-SUP-4 | Only images signed by trusted keys and pinned by digest shall be admitted to the MCP server namespace (server fleet). *(split from FR-SUP-1 in v0.4)* | S | P4 | L | IT |

### 4.12 MCP lifecycle controls (FR-MCP)

Revision-specific statements below were checked against the 2026-07-28 specification pages (details and sources: `docs/mcp-compatibility.md`). IDs were added in v0.5. Requirements of the platform go beyond the protocol text where the protocol says SHOULD or leaves a choice.

| ID | MCP phase | Requirement | Pri | Ph |
|---|---|---|---|---|
| FR-MCP-1 | Transport | TLS 1.2+ on all hops (target 1.3); no plaintext in production; the gateway shall validate the `Origin` header on HTTP transports and answer an invalid origin with 403 (a protocol MUST); servers on loopback only where local; local stdio servers only through the managed wrapper. | M | P2 |
| FR-MCP-2 | Version and capability negotiation | Only allowlisted protocol versions accepted (read per request from `_meta`; earlier revisions at initialize); capabilities offered to a server limited to those the policy permits; unexpected capabilities and extensions flagged; `server/discover` used at registration and refresh where the revision defines it; `serverInfo` never used for security decisions. | M | P2 |
| FR-MCP-3 | Session management | The platform shall maintain its own sessions, unguessable, bound to the authenticated client (FR-AUTHN-4), expiring and revocable, whether or not the MCP revision defines protocol-level sessions (revision 2026-07-28 has none and servers on it should ignore `Mcp-Session-Id`; older revisions use it). | M | P2 |
| FR-MCP-4 | Tool discovery | Filtered and hash-checked (FR-RT-1, FR-DRIFT-2). | M | P1 |
| FR-MCP-5 | Tool invocation | Full pipeline (FR-AUTHZ, FR-RT); the Phase 1 subset is deny-by-default authorization and hash-pinned allow or deny (FR-AUTHZ-1..3, FR-DRIFT-3). | M | P2 |
| FR-MCP-6 | Resources | Resource URIs validated against allowlists; URI templates treated as arguments; resource content inspected as responses. | M | P2 |
| FR-MCP-7 | Prompts | Server-supplied prompts scanned like tool descriptions and hash-pinned. | S | P2 |
| FR-MCP-8 | Notifications | Rate-limited; `list_changed` triggers re-hash; where the revision uses `subscriptions/listen` streams, the gateway opens and bounds them per server; unknown notification types ignored and logged. | M | P2 |
| FR-MCP-9 | Sampling | Sampling is deprecated in revision 2026-07-28. Denied by default; where an older revision or a server needs it and policy enables it, requests shall pass the gateway, be budgeted with iteration limits, be inspected, and require human approval for high-risk prompts. | M | P2 |
| FR-MCP-10 | Elicitation | Denied by default; if enabled, form-mode requests for passwords, keys, tokens or payment credentials shall be blocked (the specification requires URL mode for such data), the requesting server and the full target URL shall be shown to the user, and the platform shall not pre-fetch URLs. | M | P2 |
| FR-MCP-11 | Roots | Roots are deprecated and informational, not an access-control mechanism (revision 2026-07-28). Roots exposed to a server shall be limited to approved directories, validated against path traversal, and changes audited; access control shall not depend on them. | S | P2 |
| FR-MCP-12 | Version compatibility | Gateway shall record protocol version per request or session and block unsupported versions; compatibility matrix (`docs/mcp-compatibility.md`) maintained and tested on each MCP spec revision. | M | P2 |

### 4.13 Policy (FR-POL)

| ID | Requirement | Pri | Ph | Verify |
|---|---|---|---|---|
| FR-POL-1 | Policies shall be authored in Rego, versioned in source control, and unit-tested in CI (`opa test`). | M | P1 | UT |
| FR-POL-2 | Every decision shall record the policy bundle hash. | M | P1 | IT |
| FR-POL-3 | Policy bundles shall be signed; the gateway shall reject unsigned or stale bundles. | S | P3 | IT |
| FR-POL-4 | New policies shall support shadow mode (log only) before enforcement. | S | P3 | IT |

### 4.14 Audit and events (FR-AUD)

| ID | Requirement | Pri | Ph | Verify |
|---|---|---|---|---|
| FR-AUD-1 | Every allow/deny, approval, quarantine, role/config change shall create an append-only audit event with actor, subject, decision, policy hash, input digest and timestamp. | M | P1 | IT |
| FR-AUD-2 | Events shall be hash-chained; a verifier shall detect modification, deletion or reordering. | M | P1 | UT |
| FR-AUD-3 | Raw payloads shall not be stored in the audit table; store digests and redacted excerpts. Raw evidence goes to an encrypted vault with retention and legal hold. | M | P2 | DM |
| FR-AUD-4 | Chain heads shall be periodically anchored outside the database (object-lock storage or external timestamping). Without anchoring, a database administrator could rewrite the whole chain; this requirement is the mitigation. | S | P2 | IT |
| FR-AUD-5 | Events shall be exported to SIEM using OpenTelemetry/CloudEvents; control characters in untrusted fields shall be escaped to prevent log injection. | S | P2 | UT |
| FR-AUD-6 | Any decision shall be reproducible from the stored policy hash and input digest. | M | P1 | IT |
| FR-AUD-7 | When the gateway's local audit buffer is full or the audit sink is unavailable beyond its buffering capacity, the gateway shall deny high-impact calls; events shall never be dropped silently. *(added from runbook; review required)* | M | P2 | E2E |

### 4.15 Behavior analytics (FR-BEH)

| ID | Requirement | Pri | Ph | Verify |
|---|---|---|---|---|
| FR-BEH-1 | Threshold alerts (rate, denied-call ratio, new tools used, off-hours, new destinations). | S | P2 | UT |
| FR-BEH-2 | Per-agent behavior baselines and anomaly scoring; alerts include explanation and are advisory unless a policy binds them. | S | P4 | RT |

### 4.16 Incident response (FR-IR)

| ID | Requirement | Pri | Ph | Verify |
|---|---|---|---|---|
| FR-IR-1 | Incidents shall be created manually or from rules, with severity, affected agents/servers/tools, timeline and owner. | M | P2 | IT |
| FR-IR-2 | A responder shall be able to quarantine a tool, server or agent and revoke its tokens in one action; effect shall apply within 5 s. | M | P2 | E2E |
| FR-IR-3 | The system shall preserve evidence (snapshots of definitions, decisions, redacted traffic) at containment time. | M | P2 | IT |
| FR-IR-4 | Playbooks shall be executable with approval gates and shall support reapproval for recovery. | S | P4 | E2E |
| FR-IR-5 | An incident report (timeline, impact, actions, evidence index) shall be exportable. | S | P3 | DM |

### 4.17 Fleet dashboard (FR-UI)

| ID | Requirement | Pri | Ph | Verify |
|---|---|---|---|---|
| FR-UI-1 | Counts: agents, servers, tools; approved/unapproved; quarantined; critical/high findings; drift events. | M | P1 | DM |
| FR-UI-2 | Drill-down per agent, server, tool: owner, environment, criticality, risk, version history, scan evidence, permissions. | M | P1 | DM |
| FR-UI-3 | Approval queue with diff, evidence and SoD enforcement. | M | P1 | E2E |
| FR-UI-4 | Auth failures, blocked operations, data-leakage attempts, active incidents. | S | P2 | DM |
| FR-UI-5 | Relationship graph and excessive-permission view. | S | P3 | DM |
| FR-UI-6 | Compliance posture view with mandatory/guidance/voluntary distinction. | S | P3 | DM |
| FR-UI-7 | Access via enterprise OIDC with MFA and the RBAC in Section 2; UI shall meet WCAG 2.1 AA for core workflows. | M | P1 | DM |

### 4.18 Administration, configuration and multi-tenancy (FR-ADM)

| ID | Requirement | Pri | Ph | Verify |
|---|---|---|---|---|
| FR-ADM-1 | Configuration shall be declarative, validated at load, versioned, and changes audited. | M | P1 | UT |
| FR-ADM-2 | The system shall support multiple tenants with isolated data, policies and keys; per-tenant encryption keys in Phase 5. | S | P2 | PT |
| FR-ADM-3 | Notification channels (email, webhook; ServiceNow/Slack adapters later) shall be configurable per tenant. | S | P2 | IT |
| FR-ADM-4 | Data residency: a tenant's data plane shall be pinnable to a region. | S | P5 | DM |
| FR-ADM-5 | Retention shall be configurable per data class; defaults in Section 9. | M | P2 | IT |
| FR-ADM-6 | Break-glass administrative accounts shall be sealed, require a ticket and a second person's approval for each use, be session-recorded and rotated after use, and shall be unable to modify audit records or read raw evidence. *(added from runbook; review required)* | S | P2 | DM |
| FR-ADM-7 | A legal hold shall prevent deletion of the held data classes for a tenant until the compliance role releases it with a recorded reason; retention jobs shall skip held data and report skipped items. *(added in v0.5; review required)* | M | P2 | IT |
| FR-ADM-8 | Raw evidence shall be readable only by named incident and security roles through the evidence vault; every access shall be recorded with a reason, chain-of-custody records shall list who collected, transferred and accessed each item, and platform operators shall have no access. *(added in v0.5; review required)* | M | P2 | IT, DM |

### 4.19 Compliance (FR-COMP)

The platform produces **evidence and control status**. It does not determine or assert that an organization is compliant with any law or framework.

| ID | Requirement | Pri | Ph | Verify |
|---|---|---|---|---|
| FR-COMP-1 | A control catalogue shall list each control with description, owner, type (prevent/detect/respond/recover) and implementing component. | M | P3 | DM |
| FR-COMP-2 | Each control shall map to framework items, each marked as **mandatory law/regulation**, **supervisory guidance** or **voluntary framework**. | M | P3 | DM |
| FR-COMP-3 | Each finding shall record threat, component, control, mapping, risk rating, mitigation, required evidence, control owner, status. | M | P3 | IT |
| FR-COMP-4 | Evidence packs shall be exportable per control and period, signed and hash-listed. | S | P3 | DM |
| FR-COMP-5 | Mappings shall be reviewed by legal/compliance before release; versioned with review date. | M | P3 | DM |

Framework status (for the mapping matrix):

| Framework | Status type | Notes |
|---|---|---|
| EU AI Act | Mandatory law (scope depends on system role and risk class) | Applicability is determined per use case |
| GDPR | Mandatory law | Minimisation, residency, DPIA relevance for logging |
| DORA | Mandatory law for in-scope EU financial entities | ICT third-party and incident reporting |
| PCI DSS | Contractual/industry mandate for cardholder-data scope | |
| SR 11-7, FFIEC guidance | Supervisory guidance (US banking) | |
| NIST AI RMF, AI 600-1, CSF | Voluntary frameworks | |
| ISO/IEC 42001, 23894, 27001 | Voluntary standards (certifiable: 42001, 27001) | |
| SOC 2 | Voluntary attestation framework | |
| OWASP MCP / LLM Top 10 | Community guidance | OWASP MCP Top 10 project existence verified (see `docs/tech-evaluation.md` verification log); entry identifiers and current version still to be taken from the official project **[VERIFY]**; reported licence CC BY-NC-SA 4.0, so legal review before reproducing its text |
| MITRE ATLAS / ATT&CK | Knowledge bases | |

### 4.20 Observability of the platform (FR-OBS)

| ID | Requirement | Pri | Ph | Verify |
|---|---|---|---|---|
| FR-OBS-1 | All services shall emit OpenTelemetry traces, metrics and structured logs with correlation IDs; secrets redacted. | M | P1 | UT |
| FR-OBS-2 | Health, readiness and dependency checks shall be exposed; SLO dashboards for latency, error rate, decision rate. | S | P2 | DM |

### 4.21 API conventions and error model

- REST + JSON under `/v1`, OpenAPI 3.1 published; idempotency keys on create/approve operations.
- Errors use RFC 9457 problem details; error bodies never include secrets, stack traces or raw payloads.
- Gateway errors toward agents are minimal and non-informative about policy internals ("tool unavailable", "not permitted") with an opaque correlation ID.
- Pagination, filtering and sorting standardized; all list endpoints tenant-scoped.

### 4.22 Data classification (FR-DATA)

Default levels, lowest to highest: **Public**, **Internal**, **Confidential**, **Restricted**. A tenant may rename levels or add levels between them, but the order and the rules below hold. In this specification "sensitive" means Confidential or above. *(Section added in v0.4; review required. The level names are a proposed default pending approval.)*

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-DATA-1 | The platform shall define ordered data classification levels with a written meaning for each, configurable per tenant within the ordering rules above. | M | P1 | I | DM |
| FR-DATA-2 | Tools, resources and data sources in the registry shall carry a classification label assigned by the owner and confirmed at approval; unlabelled items shall be treated as Confidential. | M | P1 | I | IT |
| FR-DATA-3 | Tool outputs and session context shall inherit the highest classification of the data they contain or come from; the gateway shall use that label as the sensitive input to the taint rule (FR-RT-9), DLP policy (FR-RT-6) and the high-impact definition (FR-AUTHZ-5). | M | P2 | I, D | IT, RT |
| FR-DATA-4 | Classification labels and every change shall be audited; lowering a label shall require an approver other than the requester. | S | P2 | I, X6 | IT |

### 4.23 Key management (FR-KEY)

*(Section added in v0.5; review required.)* Platform keys include the policy-bundle signing key, image-signing identity, audit anchor credentials, token-broker and IdP client credentials, database and evidence-vault encryption keys, and break-glass secrets.

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-KEY-1 | The platform shall keep an inventory of all platform keys (class, owner role, location, purpose, rotation interval, last rotation), reviewed at least quarterly. | M | P2 | X8, G | DM |
| FR-KEY-2 | Keys shall be held in a KMS, HSM or secrets manager (non-exportable where supported); no key material shall appear in repositories, images, logs or tickets. | M | P2 | X8, G | IT, PT |
| FR-KEY-3 | Keys shall be rotated on a schedule and on suspected compromise with an overlap period; verification keys shall reach gateways before the new signing key is used. | M | P2 | X8, G | IT |
| FR-KEY-4 | Key use shall be separated by duty: signing keys usable only by the release job, anchor credentials write-only for the audit identity, break-glass secrets sealed (FR-ADM-6); no person shall hold both signing and approval roles for the same release. | M | P2 | X6, X8 | IT, DM |
| FR-KEY-5 | A written compromise procedure shall exist for each key class, including revocation, re-signing and re-approval steps, and shall be exercised at least annually. | S | P2 | X8 | DM, RT |
| FR-KEY-6 | The platform shall support a per-tenant key hierarchy and customer-managed keys as an option. | S | P5 | I | IT |

---

## 5. Threat traceability

| Threat | Requirements | First phase | Residual gap | Test cases |
|---|---|---|---|---|
| A Tool poisoning | FR-SCAN-1..4, 6, FR-RT-1, FR-SCAN-9, FR-SCAN-10 | P1 | Novel phrasing evades rules; LLM advisory only | TC-A1..A5, TC-X12 |
| B Rug pull / drift | FR-DRIFT-1..7 | P1 | Behavior change without definition change (FR-DRIFT-6, P4) | TC-B1..B4, TC-Z3 |
| C Shadowing / impersonation | FR-INV-2..4, FR-AUTHN-5, FR-AUTHZ-2 | P1/P2 | Local stdio servers (A3) | TC-C1..C3 |
| D Response injection | FR-RT-4, 5, 9, 11, 12, 13, FR-DATA-3 | P2 | Probabilistic detection; relies on blast-radius controls | TC-D1..D5, TC-X10, TC-X11 |
| E Excessive permissions | FR-AUTHZ-1..12 | P1/P2 | Quality of tool→action mapping depends on approvers | TC-E1..E4, TC-Z5, TC-Z33, TC-Z34, TC-X14 |
| F Agent spoofing | FR-ID-1..4, FR-ID-7, FR-ID-8 | P1/P2 | Compromised legitimate agent identity | TC-F1..F2, TC-X9 |
| G Auth attacks | FR-AUTHN-1..7, FR-ID-7 | P1/P2 | IdP-dependent features [VERIFY] | TC-G1..G5, TC-X13 |
| H SSRF | FR-SSRF-1..5, FR-SCAN-6, FR-RT-3, 7 | P1/P2 | Misconfigured exceptions | TC-H1..H4 |
| I Data exfiltration | FR-RT-6..9, FR-AUD-3, FR-DATA-1..4 | P2 | Encoded/steganographic leakage; low-and-slow | TC-I1..I4, TC-Z25 |
| J Memory poisoning | FR-MEM-1..4 | P4 | Not covered until P4 | TC-J1..J2 |
| K Autonomy abuse | FR-AUTO-1..6, FR-ID-5, FR-RT-9, 10 | P2 | | TC-K1..K3 |
| L Supply chain | FR-SCAN-5, FR-SUP-1..4, FR-MOD-3 | P2/P3/P4 | Server-fleet controls not covered until P3/P4 | TC-L1..L4 |
| M Inter-agent | FR-ID-4..6, FR-MEM-3 | P4 | Not covered until P4 | TC-M1..M2 |
| N Model/inference | FR-MOD-1..3, FR-RT-10 | P3/P4 | Model-internal attacks out of scope | TC-N1..N2 |
| O Tool execution | FR-RT-2, 3, FR-EXEC-1..2 | P2/P4 | Server-side bugs outside platform control | TC-O1..O3 |
| P MCP lifecycle | FR-MCP-1..12 | P1/P2 | Spec evolves; compatibility matrix | TC-P1..P4, TC-Z1, TC-Z27, TC-Z28 |
| X1 Hidden Unicode/encoding | FR-SCAN-1 | P1 | | TC-A1, TC-A5 |
| X2 Gateway bypass / unmanaged endpoints | FR-INV-5, 7, FR-RT-7 | P2/P3 | Cannot control unmanaged endpoints | TC-X2, TC-Z26 |
| X3 Sampling abuse | FR-MCP-9 | P2 | | TC-P2, TC-Z27 |
| X4 Elicitation phishing | FR-MCP-10 | P2 | | TC-P3, TC-Z28 |
| X5 Log injection | FR-AUD-5 | P2 | | TC-X5, TC-Z29 |
| X6 Insider approving malicious tool | SoD-1, SoD-2, FR-ADM-6, FR-KEY-4, FR-AUTO-6 | P1 | Collusion | TC-E4, TC-X6 |
| X7 Check-to-use gap | FR-DRIFT-7 | P2 | | TC-B4, TC-Z3 |
| X8 Gateway as high-value target | FR-AUTHN-3, FR-AUD-4, FR-ADM-2, FR-ADM-6, FR-ADM-8, FR-AUD-7, FR-KEY-1..5 | P2 | See NFR-9 | TC-X8, TC-Z30, TC-Z31, TC-Z32 |
| X9 Agent-card / discovery document spoofing | FR-ID-8, FR-ID-4 | P4 | Depends on emerging agent-to-agent standards | TC-X9 |
| X10 Non-text (multimodal) content injection | FR-RT-12 | P2 | Extraction quality limits inspection | TC-X10 |
| X11 Error-message injection | FR-RT-13 | P2 | | TC-X11 |
| X12 Scanner and detector evasion or overload | FR-SCAN-10, FR-SCAN-6 | P2 | Novel evasion between regression updates | TC-X12 |
| X13 Client registration abuse (dynamic or metadata-document) | FR-AUTHN-7 | P2 | IdP-dependent controls [VERIFY] | TC-X13 |
| X14 Approver deception or fatigue | FR-AUTHZ-9..11 | P2 | Human attention cannot be fully engineered | TC-X14, TC-Z33 |

Test cases are defined in `docs/testing/cases.md` (100 cases; threat-model Section 7 is the index). Every requirement now has a dedicated case or is covered through the control-level test lists in `controls/catalogue.md`; requirements still without a case of their own are listed in Section 21 of the test catalogue.

---

## 6. Workflows (with failure paths)

1. **Register and approve a tool.** Owner registers server → URL passes SSRF guard (fail: reject, audit) → hardened import (fail: timeout/size → registration fails, audit) → scan → findings → approver (≠ owner) reviews diff/evidence → approve (Critical: dual-control override) → version + hash stored → tool becomes available to allowlisted agents.
2. **Authorized call.** Token validated (fail: 401, audit) → session bound → registered server/agent (fail: deny) → hash pin check (fail: quarantine) → PDP (fail/unavailable: deny) → arguments guard → limits → DLP(request) → approval if high-impact (timeout: deny) → forward → inspect response (block/redact/label) → audit.
3. **Drift.** Mismatch → quarantine → notify → diff view → re-scan → re-approve (new version) or reject.
4. **Incident.** Detect → classify → contain (quarantine, revoke, kill switch) → preserve evidence → report → recover and reapprove.
5. **JIT access.** Request (reason, TTL) → approver ≠ requester → grant → auto-expiry → audit.

## 7. Logical data entities

Tenant, User/Role, Agent, Model, McpServer, Tool, ToolVersion (immutable), Scan, RuleSetVersion, Finding, Permission (static/JIT), AllowRule, Approval, Override, AuditEvent (hash chain), AnchorRecord, Incident, EvidenceItem, Control, ControlMapping, DataSource, EnterpriseSystem, GraphEdge, Session (runtime), PolicyBundle.

## 8. Interfaces

- Northbound: Management API (REST), dashboard (React), webhooks.
- Southbound: MCP servers (Streamable HTTP; stdio via wrapper), OIDC IdP, OPA, Postgres, secrets manager, SIEM, notification channels.
- Internal: interceptor plugin API with `on_request` and `on_response`; detector interface `inspect(content, context) → signals[]`.

## 9. Non-functional requirements (with measurement method)

| ID | Requirement | Target | Method |
|---|---|---|---|
| NFR-1 | Added gateway latency, deterministic path | p95 ≤ 25 ms, p99 ≤ 60 ms at 1,000 req/s per instance | Load test (k6 or equivalent) on reference hardware, payload ≤ 16 KB, mock upstream with 0 ms latency, measure gateway-added time via OTel spans; 30-minute steady state |
| NFR-2 | Inline classifier | async, or p95 ≤ 150 ms if inline | Same harness; classifier mocked and real |
| NFR-3 | Availability (P5) | 99.95% monthly | Synthetic probes across zones; error budget report |
| NFR-4 | Recovery (P5) | RPO ≤ 5 min, RTO ≤ 30 min | Quarterly DR exercise with timed evidence |
| NFR-5 | Scale (to validate) | 10,000 concurrent sessions, 5,000 calls/s cluster | Soak and stress tests; results published |
| NFR-6 | Audit retention | Default 13 months hot, 7 years cold (**placeholder pending legal input**: no legal basis is stated, and storage-limitation duties for personal data in excerpts may require shorter or per-tenant values); configurable per tenant/regulation; legal hold overrides | Configuration test; retention job report |
| NFR-7 | Reproducibility | 100% of decisions replayable | Replay test over sampled decisions |
| NFR-8 | Isolation | No cross-tenant data access | Negative penetration tests |
| NFR-9 | Platform security | Signed images, SBOM, no long-lived upstream secrets in gateway memory, separate admin plane, dependency scan gates in CI | CI gate evidence; penetration test |
| NFR-10 | Accessibility | WCAG 2.1 AA on core flows | Automated + manual audit |

Targets are proposals; none has been measured.

## 10. Detector quality budgets

| Detector | Measure | Initial budget | Process |
|---|---|---|---|
| Tool-description rules | Recall / precision on a labelled corpus (published poisoned samples + benign enterprise tools) | ≥ 95% / ≥ 90% | Corpus versioned; regression in CI; monthly review |
| Response injection | Recall on injection test set; false-block rate on benign traffic | Recall target set after Phase 2 baseline; false-block ≤ 0.5% of benign calls in shadow mode | Run in shadow mode before enforce |
| DLP | Precision per entity type | Luhn/checksum types ≥ 99%; free-text PII measured and tuned per tenant | Per-tenant tuning |
| Anomaly | Alert volume per agent per day | ≤ 5 reviewed alerts per 100 agents per day | Weekly tuning |

Known bypasses to track: paraphrased instructions, multilingual and encoded payloads, split-across-calls payloads, benign-looking tool chains, low-and-slow exfiltration. Each shall have at least one regression test or be listed as an accepted residual risk.

## 11. Acceptance criteria

MVP (P1):
- AC-1 (FR-SCAN-1..4): Seeded poisoned tools (hidden Unicode, override phrase, credential request) score High/Critical with evidence and cannot be approved without SoD-2 override.
- AC-2 (FR-DRIFT-1..5): Changing any hashed field quarantines the tool by the next `tools/list`; zero calls to it succeed; diff shown.
- AC-3 (FR-AUTHZ-1..3, FR-INV-4): No grant → deny; grant → allow; read-only grant cannot write/delete; unregistered agent or server denied.
- AC-4 (FR-SSRF-1..5): Server URLs resolving to loopback, 169.254.169.254, RFC 1918, IPv4-mapped IPv6, alternate encodings, or reached by redirect are rejected; a hostname that changes its DNS answer between check and connect still connects only to the validated IP.
- AC-5 (FR-AUD-1, 2, 6): Each decision has an audit event with policy hash; verifier passes; tampering with, deleting or reordering a row is detected.
- AC-6 (FR-UI-1..3, 7): Dashboard shows counters, drill-down and approval queue for a seeded fleet; requester cannot approve own request.
- AC-7 (FR-AUTHZ-8): Stopping OPA causes calls to be denied.
- AC-8 (FR-SCAN-6): Importer rejects an oversized, deeply nested, slow, and redirecting response from a hostile test server.
- AC-9 (FR-AUTHN-6): Log redaction test finds no token or secret in logs under error conditions. Test case: TC-G5.

Phase 2 (P2) criteria *(added in v0.5)*:
- AC-10 (NFR-1, NFR-2): Added gateway latency and inline-classifier latency meet the targets in the load test with the method of Section 9 (TC-Z14, TC-Z15).
- AC-11 (FR-RT-4..13, FR-DATA-3): Injection, taint, DLP and classification scenarios pass and shadow-mode false-block rate stays within the budget before enforcement (TC-D1..D5, TC-I1..I4, TC-X10, TC-X11, TC-Z25).
- AC-12 (FR-AUTHN-2..5, 7, FR-ID-3, 7): Replay, audience, session and registration abuse are refused in the recorded token-binding mode (TC-G1, TC-G3, TC-G4, TC-X13).
- AC-13 (FR-AUTHZ-4, 5, 9..12, FR-AUTO-1..6): JIT, bound approvals, step-up, limits, kill switch and emergency policy behave as specified (TC-E3, TC-D4, TC-K1..K3, TC-X14, TC-Z33, TC-Z34).
- AC-14 (FR-RT-7, FR-SUP-1): Servers cannot bypass the gateway or reach unlisted destinations, and only compliant platform images are admitted (TC-I4, TC-X2, TC-Z26, TC-L4).
- AC-15 (FR-AUD-3..5, 7, FR-ADM-7, 8, FR-KEY-1..5): Anchoring, audit capacity, retention and legal hold, evidence access and key management controls pass (TC-Z22, TC-Z23, TC-Z19, TC-Z30, TC-Z31, TC-Z32, TC-X5).
- AC-16 (FR-MCP-1..12): Protocol lifecycle controls pass (TC-P1..P4, TC-Z27, TC-Z28).
- AC-17 (NFR-5): Scale and soak targets hold (TC-Z18).

Phase 3 (P3) criteria *(added in v0.5)*:
- AC-18 (FR-COMP-1..5): An evidence pack for a chosen control and period is reviewed by an auditor and mappings carry reviewer names and dates; every mapping states mandatory, guidance or voluntary.
- AC-19 (FR-SCAN-7, 9, FR-POL-3, 4, FR-UI-5, 6): Re-scans, signed bundles with shadow mode, and the fleet views behave as specified (TC-Z12, TC-X6, TC-Z9).

Phase 4 (P4) criteria *(added in v0.5)*:
- AC-20 (FR-MEM-1..4, FR-ID-4..6, 8, FR-SUP-2, 4, FR-EXEC-1..2): Memory, delegation, agent-card, server-fleet supply-chain and sandbox controls pass (TC-J1, TC-J2, TC-M1, TC-M2, TC-X9, TC-L1, TC-L2, TC-N1).
- AC-21 (FR-IR-4): Automated playbooks run with approval gates in staging and produce an incident report.

Phase 5 (P5) criteria *(added in v0.5)*:
- AC-22 (NFR-3, NFR-4): Measured availability and the timed disaster-recovery exercise meet the targets and the restored audit chain verifies (TC-Z16, TC-Z17).
- AC-23 (FR-ADM-4, FR-KEY-6, NFR-8): Residency pinning, per-tenant keys and tenant isolation hold in every tenancy model offered (TC-I3).
- AC-24 (NFR-9): The gateway and control plane survive an external penetration test and a compromise exercise with no long-lived secret or cross-tenant access obtained (TC-X8).

Acceptance-criteria-to-test mapping (MVP): AC-1 ← TC-A1..A3; AC-2 ← TC-B1, B2; AC-3 ← TC-E1, C3, F1; AC-4 ← TC-H1..H4; AC-5 ← TC-Z6 (chain verification; anchoring is covered by TC-Z22 in Phase 2); AC-6 ← TC-E4, TC-Z7; AC-7 ← TC-Z5; AC-8 ← TC-Z2; AC-9 ← TC-G5. The later-phase criteria list their cases inline.

## 12. Risks, assumptions and open decisions

Proposed resolutions are recommendations awaiting approval by the named owners; none is settled. Verified facts come from the verification log in `docs/tech-evaluation.md`.

| Item | Impact | Owner / next step | Proposed resolution (pending approval) |
|---|---|---|---|
| Build vs extend an open-source MCP gateway (ADR-1) | Schedule, maintenance | Spike S1 before Phase 2 | Custom thin gateway for the MVP; decide the Phase 2 base after S1 (candidates verified to exist: agentgateway, IBM ContextForge, Docker MCP Gateway, Envoy AI Gateway with MCP support since its v0.4) |
| Production IdP and support for DPoP/mTLS binding and token exchange (ADR-2) | FR-AUTHN-2/3 feasibility | Decide IdP; test features | Keycloak for development (DPoP supported from 26.4; token exchange V2 limited to internal-to-internal use); production IdP capability matrix from spike S2 |
| SIEM/SOAR target | Integration scope | Customer decision | None proposed |
| Approval channel (ADR-3) | UX and SoD enforcement | Product owner | Dashboard approval queue in the MVP; webhook adapters for ticketing/chat later |
| Single vs multi-tenant deployment first (ADR-4) | Schema and isolation effort | Decide before P1 schema freeze | Shared multi-tenant with tenant ID on every row and PostgreSQL row-level security; dedicated namespace/database or cluster models as later options |
| Policy language (ADR-6) | Policy authoring and tooling | Decide before P1 policies | Rego on OPA |
| Jurisdictions and regulators for the compliance matrix | Mapping scope | Compliance input | None proposed |
| MCP spec churn | Rework | Version-pinned compatibility matrix; track spec revisions | Pin 2026-07-28 as reference; re-review on each revision |
| Detector false positives hindering adoption | Adoption | Shadow mode; budgets in Section 10 | Keep |
| Unmanaged endpoints and local stdio servers | Coverage | Discovery, reporting, wrapper; accepted residual risk | Keep |

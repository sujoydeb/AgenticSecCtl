# Functional Specification: AgenticSecCtl
**Enterprise Agentic AI & MCP Security Gateway and Governance Platform**

| | |
|---|---|
| Version | 0.2 (draft for review) |
| Supersedes | 0.1 |
| Stack decisions | Python/FastAPI, Postgres, OPA, React, cloud-neutral Kubernetes; Redis/Kafka from Phase 2 |
| Conventions | "shall" = mandatory requirement. **[VERIFY]** = vendor, product or protocol claim not yet checked against current documentation. |

## 0. Change log (v0.1 → v0.2)

Review of v0.1 found the following. Each is fixed in this version.

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

Trust zones, component responsibilities and the interceptor pipeline are defined in the architecture document (to be written; summary in the design plan). Assumptions:
- A1: An OIDC identity provider is available (Keycloak for development; production IdP undecided).
- A2: MCP servers and all content they return are untrusted until registered and pinned; even then, response content stays untrusted.
- A3: MVP gateway covers Streamable HTTP. Local stdio servers need a wrapper (Phase 2).
- A4: Detectors are probabilistic. Enforcement of high-impact actions never depends on a single detector or on an LLM classifier.

---

## 4. Functional requirements

Priority: **M** must, **S** should, **C** could. Phase: **P1** MVP, **P2** runtime protection, **P3** governance, **P4** advanced threat protection, **P5** enterprise production. "Threats" refer to Section 5 (A–P plus added vectors X1–X8). "Verify" is the test method: UT unit, IT integration, E2E end-to-end, RT red-team, PT penetration, FZ fuzz, DM demonstration/inspection.

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

### 4.5 Authentication (FR-AUTHN)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-AUTHN-1 | The gateway shall validate token signature, issuer, expiry, audience (the gateway/resource identifier) and scope on every request. [VERIFY against current MCP authorization spec] | M | P1 | G | UT, IT |
| FR-AUTHN-2 | Access tokens shall be sender-constrained (DPoP or mTLS binding) where the IdP supports it, with short lifetime (default ≤ 10 min) and revocation. One-time artifacts (approval tokens, exchange requests) shall use `jti` single-use. [VERIFY IdP support] | S | P2 | G | IT, PT |
| FR-AUTHN-3 | The gateway shall not pass client tokens through to MCP servers. It shall obtain audience-bound upstream tokens by token exchange or use server-specific credentials from the secrets broker. [VERIFY] | M | P2 | G | IT, PT |
| FR-AUTHN-4 | Sessions shall be bound to the authenticated client; use of a session ID by a different client or network identity shall be rejected and alerted. | M | P2 | G | PT |
| FR-AUTHN-5 | Server identity shall be validated (TLS chain, pinned certificate or JWKS per registry entry); failure shall deny and raise an alert. | M | P2 | C | IT |
| FR-AUTHN-6 | Secrets and tokens shall never appear in logs, findings or UI; this shall be enforced by log redaction tests. | M | P1 | G, I | UT |

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

### 4.8 Agent autonomy controls (FR-AUTO)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-AUTO-1 | Per-agent and per-session limits shall apply to tool calls, distinct tools, depth of delegation, wall-clock time and cost/tokens. | M | P2 | K | E2E |
| FR-AUTO-2 | The system shall detect repeating call sequences (loops) and suspend the session. | S | P2 | K | UT |
| FR-AUTO-3 | Autonomous financial or irreversible transactions shall require approval unless a policy explicitly permits a bounded amount and counterparty. | M | P2 | K | E2E |
| FR-AUTO-4 | A kill switch shall suspend an agent or all agents of a tenant within 5 s of command. | M | P2 | K | E2E |

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
| FR-SSRF-1 | Every outbound connection initiated by the platform (registration, import, discovery, health check, proxying) shall pass the SSRF guard. | M | P1 | H | UT, PT |
| FR-SSRF-2 | The guard shall resolve DNS, validate every returned address against the blocklist (loopback, link-local including 169.254.169.254, RFC 1918/ULA, multicast, unspecified, IPv4-mapped IPv6, metadata hostnames) and connect to the validated IP (resolve-then-pin) to defeat rebinding. | M | P1 | H | UT, PT |
| FR-SSRF-3 | Redirects shall be disabled by default; if enabled, each hop shall be re-validated, max 3. | M | P1 | H | UT |
| FR-SSRF-4 | Alternate encodings (decimal, octal, hex, IPv6 forms, userinfo tricks, unicode hosts) shall be normalized before checks. | M | P1 | H | FZ |
| FR-SSRF-5 | Exceptions (internal servers) shall be explicit per-server allowlist entries with owner approval and expiry. | M | P1 | H | IT |

### 4.11 Tool execution and supply chain (FR-EXEC, FR-SUP)

| ID | Requirement | Pri | Ph | Threats | Verify |
|---|---|---|---|---|---|
| FR-EXEC-1 | Server-owner guidance and admission policy shall require platform-hosted MCP servers to run non-root, read-only filesystem, no privileged capabilities, resource limits, and a sandboxed runtime for tools executing code. [VERIFY runtime availability per cloud] | S | P4 | O | DM, PT |
| FR-EXEC-2 | File upload/download tools shall enforce type, size and malware-scan checks. | S | P4 | O | IT |
| FR-SUP-1 | Only images signed by trusted keys and pinned by digest shall be admitted to the server namespace. | S | P4 | L | IT |
| FR-SUP-2 | Server package names shall be checked for typosquatting against registry allowlists and known popular names. | S | P4 | L | UT |
| FR-SUP-3 | Third-party servers shall go through a documented intake (SBOM, owner, licence, vulnerability status) before approval. | S | P3 | L | DM |

### 4.12 MCP lifecycle controls (FR-MCP)

| MCP phase | Requirement | Pri | Ph |
|---|---|---|---|
| Transport | TLS 1.2+ on all hops (target 1.3); no plaintext in production; Origin/Host validation on HTTP transports; local transports only through the managed wrapper. [VERIFY current spec] | M | P2 |
| Initialize / capability negotiation | Only allowlisted protocol versions accepted; capabilities offered to a server limited to those the policy permits; unexpected capabilities flagged. | M | P2 |
| Session management | Session IDs unguessable, bound to client (FR-AUTHN-4), expire, and revocable. | M | P2 |
| Tool discovery | Filtered and hash-checked (FR-RT-1, FR-DRIFT-2). | M | P1 |
| Tool invocation | Full pipeline (FR-AUTHZ, FR-RT). | M | P1/P2 |
| Resources | Resource URIs validated against allowlists; URI templates treated as arguments; resource content inspected as responses. | M | P2 |
| Prompts | Server-supplied prompts scanned like tool descriptions and hash-pinned. | S | P2 |
| Notifications | Rate-limited; `list_changed` triggers re-hash; unknown notification types ignored and logged. | M | P2 |
| Sampling | Denied by default; if enabled per server, requests shall pass the gateway, be budgeted, inspected, and require approval for high-risk prompts. | M | P2 |
| Elicitation | Denied by default; if enabled, requests asking for credentials, tokens or secrets shall be blocked; user-visible source labelling required. | M | P2 |
| Roots | Roots exposed to a server limited to approved directories; changes audited. | S | P2 |
| Version compatibility | Gateway shall record protocol version per session and block unsupported versions; compatibility matrix maintained and tested on each MCP spec revision. | M | P2 |

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
| OWASP MCP / LLM Top 10 | Community guidance | MCP list status [VERIFY] |
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

---

## 5. Threat traceability

| Threat | Requirements | First phase | Residual gap |
|---|---|---|---|
| A Tool poisoning | FR-SCAN-1..4, 6, FR-RT-1 | P1 | Novel phrasing evades rules; LLM advisory only |
| B Rug pull / drift | FR-DRIFT-1..7 | P1 | Behavior change without definition change (FR-DRIFT-6, P4) |
| C Shadowing / impersonation | FR-INV-2..4, FR-AUTHN-5, FR-AUTHZ-2 | P1/P2 | Local stdio servers (A3) |
| D Response injection | FR-RT-4, 5, 9, 11 | P2 | Probabilistic detection; relies on blast-radius controls |
| E Excessive permissions | FR-AUTHZ-1..8 | P1/P2 | Quality of tool→action mapping depends on approvers |
| F Agent spoofing | FR-ID-1..4 | P1/P2 | Compromised legitimate agent identity |
| G Auth attacks | FR-AUTHN-1..6 | P1/P2 | IdP-dependent features [VERIFY] |
| H SSRF | FR-SSRF-1..5, FR-SCAN-6, FR-RT-3, 7 | P1/P2 | Misconfigured exceptions |
| I Data exfiltration | FR-RT-6..9, FR-AUD-3 | P2 | Encoded/steganographic leakage; low-and-slow |
| J Memory poisoning | FR-MEM-1..4 | P4 | Not covered until P4 |
| K Autonomy abuse | FR-AUTO-1..4, FR-ID-5, FR-RT-9, 10 | P2 | |
| L Supply chain | FR-SCAN-5, FR-SUP-1..3, FR-MOD-3 | P3/P4 | Not covered until P3/P4 |
| M Inter-agent | FR-ID-4..6, FR-MEM-3 | P4 | Not covered until P4 |
| N Model/inference | FR-MOD-1..3, FR-RT-10 | P3/P4 | Model-internal attacks out of scope |
| O Tool execution | FR-RT-2, 3, FR-EXEC-1..2 | P2/P4 | Server-side bugs outside platform control |
| P MCP lifecycle | Section 4.12 | P1/P2 | Spec evolves; compatibility matrix |
| X1 Hidden Unicode/encoding | FR-SCAN-1 | P1 | |
| X2 Gateway bypass / unmanaged endpoints | FR-INV-5, 7, FR-RT-7 | P2/P3 | Cannot control unmanaged endpoints |
| X3 Sampling abuse | Section 4.12 | P2 | |
| X4 Elicitation phishing | Section 4.12 | P2 | |
| X5 Log injection | FR-AUD-5 | P2 | |
| X6 Insider approving malicious tool | SoD-1, SoD-2 | P1 | Collusion |
| X7 Check-to-use gap | FR-DRIFT-7 | P2 | |
| X8 Gateway as high-value target | FR-AUTHN-3, FR-AUD-4, FR-ADM-2 | P2 | See NFR-9 |

Test case IDs (≥ 30, per the brief) will be added to this table when `docs/testing/cases.md` is written.

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
| NFR-6 | Audit retention | Default 13 months hot, 7 years cold; configurable per tenant/regulation; legal hold overrides | Configuration test; retention job report |
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
- AC-9 (FR-AUTHN-6): Log redaction test finds no token or secret in logs under error conditions.

Phase 2+ acceptance criteria are defined per requirement via the Verify column and the test catalogue.

## 12. Risks, assumptions and open decisions

| Item | Impact | Owner / next step |
|---|---|---|
| Build vs extend an open-source MCP gateway | Schedule, maintenance | Technology evaluation [VERIFY] before Phase 2 |
| Production IdP and support for DPoP/mTLS binding and token exchange | FR-AUTHN-2/3 feasibility | Decide IdP; test features [VERIFY] |
| SIEM/SOAR target | Integration scope | Customer decision |
| Approval channel (dashboard only vs ServiceNow/Slack) | UX and SoD enforcement | Customer decision |
| Single vs multi-tenant deployment first | Schema and isolation effort | Decide before P1 schema freeze |
| Jurisdictions and regulators for the compliance matrix | Mapping scope | Compliance input |
| MCP spec churn | Rework | Version-pinned compatibility matrix; track spec revisions |
| Detector false positives hindering adoption | Adoption | Shadow mode; budgets in Section 10 |
| Unmanaged endpoints and local stdio servers | Coverage | Discovery, reporting, wrapper; accepted residual risk |

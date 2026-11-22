# Critical Architecture Assessment: AgenticSecCtl

| | |
|---|---|
| Version | 0.2 (draft for review; closes gap A1 and, with Section 7.1, gap A6 in `docs/reviewgap.md`) |
| Depends on | `Plan/functional-spec.md` v0.5, `Plan/architecture.md` v0.4, `Plan/threat-model.md` v0.4, `docs/tech-evaluation.md` v0.2, `controls/catalogue.md` v0.3, `docs/testing/cases.md` v0.4, `docs/roadmap.md` v0.3 |
| Purpose | The assessment the master brief asks for before any implementation: missing attack vectors, weak assumptions, architectural gaps, tools to reuse, controls that need deterministic enforcement versus controls that can use LLM-based analysis, performance bottlenecks, and regulatory and operational risks. Each finding points to where the repository answers it. |
| Status | Written after the design documents, so it consolidates and cross-checks them; it is not the original planning document. Facts marked *search-verified* come from the verification log in `docs/tech-evaluation.md` (mostly secondary sources); everything else is background knowledge and is tagged **[VERIFY]**. |

## 1. Summary of the assessment

1. The central design bet is sound: a gateway that enforces deterministic controls on every agent-to-server message, with LLM-based detection only as an advisory signal. Scanning tool descriptions alone cannot protect MCP, because most risk is at run time (responses, arguments, sessions, delegation).
2. The largest remaining weaknesses are not in the control design but in assumptions that are still unproven: that all traffic can be forced through the gateway, that approvers will approve well, that detectors reach their quality budgets, that the chosen IdP supports sender-constrained tokens, and that the gateway meets the latency budget.
3. Several vectors were added after the first assessment (Section 2) and now have requirements, controls and tests; a few remain outside platform scope by design (Section 2.3).
4. The decisions that most change the architecture (gateway base, identity provider, tenancy model, stdio handling) are still open; proposals are recorded, not settled (Section 9).

## 2. Missing attack vectors

### 2.1 Vectors beyond the brief's list (A to P) and where they are handled

| Vector | Threat ID | Requirement | Control | Test |
|---|---|---|---|---|
| Hidden text: zero-width, bidirectional, homoglyph, ANSI | X1 | FR-SCAN-1 | CTL-02 | TC-A1, TC-A5 |
| Gateway bypass: local stdio servers, IDE-embedded agents, direct SaaS connectors | X2 | FR-INV-5..7, FR-RT-7 | CTL-26, CTL-08 | TC-X2 |
| Sampling abuse (server makes the client model work on the user's budget) | X3 | Spec Section 4.12 | CTL-18 | TC-P2 |
| Elicitation phishing for credentials | X4 | Spec Section 4.12 | CTL-18 | TC-P3 |
| Log injection into the SIEM | X5 | FR-AUD-5 | CTL-13 | TC-X5 |
| Insider approves a malicious tool or edits policy | X6 | SoD-1..3, FR-ADM-6 | CTL-23, CTL-16 | TC-E4, TC-X6, TC-Z24 |
| Check-to-use gap between listing and calling | X7 | FR-DRIFT-7 | CTL-03 | TC-B4, TC-Z3 |
| Gateway or control-plane compromise | X8 | NFR-9, FR-AUD-7 | CTL-27, CTL-23, CTL-13 | TC-X8 |
| Agent-card or discovery-document spoofing | X9 | FR-ID-8 | CTL-20 | TC-X9 |
| Non-text (multimodal) content injection | X10 | FR-RT-12 | CTL-09 | TC-X10 |
| Error-message injection | X11 | FR-RT-13 | CTL-09 | TC-X11 |
| Scanner and detector evasion or overload | X12 | FR-SCAN-10 | CTL-02 | TC-X12 |
| Client registration abuse (dynamic or metadata-document) | X13 | FR-AUTHN-7 | CTL-05 | TC-X13 |
| Cross-tool data laundering (private data, untrusted content, external send) | covered under D and I | FR-RT-9, FR-DATA-3 | CTL-09, CTL-29 | TC-D5, TC-Z25 |
| `tools/list_changed` used as a runtime rug-pull trigger | B | FR-DRIFT-2 | CTL-03 | TC-B1, TC-B4 |
| Tool output-schema poisoning | A, B | FR-DRIFT-1 (output schema is hashed) | CTL-03 | TC-B2 |
| Time-of-check to time-of-use between scan and invoke | X7 | FR-DRIFT-7 | CTL-03 | TC-Z3 |

### 2.2 Context from verification

The current MCP specification revision (2026-07-28, *search-verified*) makes authorization optional for implementations, expects HTTP transports to follow the OAuth-based authorization specification with protected resource metadata (RFC 9728), expects stdio transports to take credentials from the environment, and deprecates dynamic client registration in favour of client ID metadata documents. Consequences for this design: the platform cannot assume that servers authenticate callers (assumptions A5, A6 in the spec), registration abuse must cover both registration styles (X13), and stdio servers need a managed wrapper (ADR-5).

### 2.3 Deliberately out of scope or only partly covered

- Model-internal risks (training-data memorisation, system-prompt leakage, adversarial examples against the model itself) are outside the platform's reach; the platform limits the *consequences* through approvals, taint and egress controls. This is stated in threat N and the compliance matrix shared-responsibility table.
- Social engineering of approvers and approval fatigue are acknowledged (CTL-07, CTL-28) but approval content and step-up authentication are not yet specified (gap H4 in `docs/reviewgap.md`).
- Unmanaged endpoints remain a reported, accepted residual risk (X2).

## 3. Weak assumptions

| Assumption (as commonly made) | Why it is weak | What the design does instead | Residual |
|---|---|---|---|
| A tool-description scanner protects MCP | Covers discovery time only | Runtime pipeline: pinning, authorization, argument guards, response inspection, DLP (architecture Section 5) | Detectors are probabilistic |
| The gateway sees all traffic | Not for local stdio servers, IDE-embedded agents, direct connectors | Discovery, managed wrapper, network policy, honest coverage reporting (CTL-26) | Unmanaged endpoints |
| A hash of the definition proves integrity | It proves sameness, not safety; behaviour can change without a definition change | Call-time re-check, response inspection, baselines (CTL-03, CTL-09) | Behaviour-only change until Phase 4 baselines |
| Tool annotations (read-only hint and similar) are trustworthy | They are hints from an untrusted server | Action class set by the owner and approver in the registry; annotations never used for authorization (FR-AUTHZ intro) | Wrong mapping at approval |
| OAuth scopes equal permissions | Scopes are coarse | Policy on (agent, tool, action class, resource, arguments digest, context) (CTL-06) | Resource patterns written by owners |
| Prompt-injection detection can be made reliable | It cannot | Taint rule, approvals, egress allowlists; detectors advisory (CTL-09, FR-RT-11) | Medium to high residual risk |
| Sender-constrained tokens are available | Depends on the IdP; Keycloak supports DPoP from 26.4 but its token exchange V2 is limited to internal-to-internal use (*search-verified*) | Documented fallback of short-lived tokens plus mTLS; test records the mode (TC-G1) | Fallback has a replay window |
| Servers authenticate and authorize callers | Authorization is optional in the current MCP revision | Gateway enforces authorization regardless (A6) | Servers behind the gateway still trust it fully |
| An LLM classifier can be a security control | It can be evaded and can be attacked | Advisory only; never the sole control of a high-impact decision (A4, FR-RT-11) | Detector quality budgets unproven |
| Approvers will review carefully | Fatigue, summaries can mislead | Dual control for Critical overrides, argument-bound approvals, metrics | Collusion and fatigue |
| Fail-open keeps agents productive during an outage | It silently removes protection | Fail-closed by default; tenant allowlist for read-only low-risk tools, flagged in audit | Availability impact |

## 4. Architectural gaps found and where they stand

| Gap | Status |
|---|---|
| No single trust model for MCP servers of different origin (first-party, third-party, stdio) | Zones Z3a, Z3b, Z3c in architecture Section 2; third-party intake in FR-SUP-3 |
| Gateway is a high-value target and single point of failure | Plane separation, no long-lived secrets, HA design, penetration test (CTL-27, CTL-24, deployment architecture) |
| Policy decision latency and cache correctness unproven | Spike S3; short-TTL decision cache keyed on policy hash and input digest |
| Tenancy model undecided | ADR-4 proposal: shared multi-tenant with row-level security; data model in `docs/data-model.md` |
| Audit integrity relies on a hash chain that is tamper-evident only | External anchoring in a separate account (FR-AUD-4, TC-Z22); residual window before the first anchor |
| Data sensitivity had no model | Data classification added (FR-DATA-1..4, CTL-29) |
| Stdio servers outside the network boundary | ADR-5 proposal: managed wrapper |
| No API or data-model specification | `docs/api-specification.md`, `docs/api/openapi.yaml` and `docs/data-model.md` (draft) |
| Key management for platform keys scattered across documents | Open (gap H3 in `docs/reviewgap.md`) |
| Approval content and step-up authentication unspecified | Open (gap H4) |

## 5. Existing tools to reuse (and what is verified)

Principle: integrate mature components for policy, identity, DLP, SBOM, signing, telemetry and secrets; custom code only for MCP-aware control logic. Verification status below comes from `docs/tech-evaluation.md`; "unverified" means background knowledge only.

| Need | Candidate | Status |
|---|---|---|
| Policy | OPA/Rego | Graduated CNCF project (*search-verified*); licence to be confirmed from the repository |
| Identity (development) | Keycloak | DPoP supported from 26.4; token exchange V2 partial (*search-verified*) |
| MCP gateway base | agentgateway; IBM ContextForge; Docker MCP Gateway; Envoy AI Gateway | Existence and licences search-verified (Apache-2.0, Apache-2.0, MIT, MCP support since v0.4); capability fit untested (spike S1) |
| Tool scanning | Cisco mcp-scanner; Snyk agent-scan (formerly Invariant mcp-scan) | Both exist and are Apache-2.0 per third-party indexes; Snyk's scanner sends tool names and descriptions to Snyk's API (third-party summary), which makes tenant opt-in essential (FR-SCAN-8) |
| DLP | Presidio-style recognisers, secret scanners | Licence reported MIT (secondary); performance untested (spike S4) |
| SBOM, scanning, signing | Syft, Grype, Trivy, cosign, SLSA provenance | Unverified |
| Cache | Redis (AGPLv3 option from Redis 8) or Valkey (BSD fork) | Search-verified; choice is a licensing decision |
| Admission | Kyverno or OPA Gatekeeper | Unverified; decision open |
| Telemetry | OpenTelemetry | Unverified (GenAI conventions maturity) |

## 6. Deterministic enforcement versus LLM-based analysis

| Must be deterministic (enforcement) | May use LLM or ML analysis (advisory) |
|---|---|
| Token validation, audience, scope, expiry, sender constraint, revocation | Secondary classification of descriptions and responses |
| Authorization decisions (OPA), deny by default | Triage, de-duplication and explanation of findings |
| Hash pin, drift detection, quarantine | Incident narratives and report drafts |
| SSRF guard, egress allowlists | Suggested policy tightening (human reviewed) |
| DLP patterns, checksums, classification inheritance | Red-team payload generation in the test environment |
| Limits, budgets, loop and depth checks | Anomaly scoring (Phase 4), alert only |
| Human approval for high-impact actions; audit chain | |

The deterministic column is the only class that may enforce a high-impact decision alone (control catalogue enforcement classes; FR-RT-11, FR-SCAN-3).

## 7. Performance bottlenecks

| Bottleneck | Mitigation | Evidence needed |
|---|---|---|
| LLM or ML classifier on the hot path | Tiering: deterministic inline under 5 ms, small local model asynchronous or sampled, LLM only for escalation | TC-Z15 |
| Response inspection of large or streamed payloads | Size caps, chunked inspection, per-session limits | TC-Z4, TC-Z14 |
| OPA call per invocation | Local sidecar, decision cache keyed on policy hash and input digest | Spike S3, TC-Z14 |
| Token validation and revocation lookups | Local signature validation; cached revocation list; deny when lookup fails | TC-G1, TC-Z14 |
| Audit write amplification | Outbox with batching; chain computed by the audit service; Kafka only when volume demands | TC-Z18 |
| Hash recomputation on every list and notification | Rate-limited re-hash; cached canonical forms | TC-P4 |
| Database as the shared bottleneck | Pooling, read replicas, partitioned audit tables | TC-Z18 |

### 7.1 Security implications of architectural choices (trade-offs)

Each row states the choice, what it buys, the security consequence, the residual risk, and who should accept it. "Acceptor" is a governance role (`docs/governance.md`).

| Choice | Benefit | Security consequence | Residual risk | Acceptor |
|---|---|---|---|---|
| Fail closed on PDP, registry, bundle, revocation or audit loss | No silent loss of protection | Outages of the platform stop agents (availability cost) | Business disruption during incidents | Product owner |
| Tenant fail-open allowlist for read-only low-risk tools | Keeps low-risk reads working in an outage | Reads happen without a fresh decision; flagged and reviewed | Misclassified tool in the allowlist | Security architect with tenant owner |
| 60-second registry and definition cache | Lower latency and database load | Up to 60 seconds of stale state, closed at call time by the hash check; revocation and quarantine propagate within 5 seconds by events | Event delivery failure widens the window to the cache TTL | Security architect |
| Decision cache keyed on policy hash and input digest | Fewer policy calls | A decision may outlive a grant revocation by the cache TTL unless events invalidate it | Short stale window | Security architect |
| Deterministic checks inline, classifiers asynchronous or advisory | Meets latency budget | Asynchronous findings cannot block the current call | Missed injections are caught only after the fact; blast-radius controls compensate | Security architect |
| Shared multi-tenant platform (ADR-4 proposal) | Lower cost and operations | Larger blast radius for a platform or isolation bug | Cross-tenant leakage if row-level security fails; dedicated models are an option | Sponsor, security architect |
| Custom thin gateway first (ADR-1 proposal) | Fast, controlled MVP | Home-grown proxy code is attack surface and must meet the latency budget | Maintenance and performance risk; decision revisited after spike S1 | Security architect |
| Managed wrapper for stdio servers (ADR-5 proposal) | Brings local servers inside the pipeline | The wrapper becomes a trusted component holding brokered credentials | Wrapper compromise | Security architect |
| Hash chain with external anchors | Tamper evidence | Anchor store becomes critical infrastructure; an unanchored window exists | Rewrite before the first anchor | Security architect |
| Digests and redacted excerpts instead of raw payloads | Privacy and smaller blast radius | Investigations lack full payloads unless the evidence vault holds them | Gaps in forensics for non-incident traffic | Compliance liaison |
| Human approval for high-impact actions | Strong control on irreversible actions | Approver fatigue and deception become the weakness; latency for the agent | Rubber-stamping (threat X14) | Product owner |
| Sender-constrained tokens where the IdP allows | Stops stolen-token replay | Depends on IdP support and client libraries; fallback is weaker | Replay window in fallback mode | Security architect |
| Sandbox pool for untrusted server code | Limits container escape impact | Cost, compatibility and performance overhead | Runtime escape vulnerabilities | Platform operator |
| Strict default-deny network policy | Blocks lateral movement and bypass | Breakage risk when a needed flow is not allowed; startup ordering | Misconfigured exceptions | Platform operator |

## 8. Regulatory and operational risks

- A mapping is not compliance (compliance matrix Section 1); mappings are only partly verified and not legally reviewed.
- Logging prompts and responses creates its own privacy, retention and residency problem; the design stores digests and redacted excerpts and keeps raw evidence in an encrypted vault. The default retention (13 months hot, 7 years cold) has no stated legal basis (gap D5).
- Fail-closed makes platform outages business outages; mitigated by HA, tested degradation and a narrow tenant allowlist.
- Sending tool content to an external classifier or scanner service is a data transfer; it needs tenant opt-in and a self-hosted option (FR-SCAN-8, TC-Z13).
- The platform needs its own privacy assessment (what it stores about users, agents and tenants); not yet written (gap H2).
- Operational maturity (on-call, runbook exercises, key rotation, break-glass discipline) is a risk to every control; the runbook and playbooks are untested drafts.

## 9. Open decisions that most change the architecture

| ADR | Proposed (pending approval) | Where recorded |
|---|---|---|
| ADR-1 gateway | Custom thin gateway for the MVP; decide the Phase 2 base after spike S1 | Architecture Section 12 |
| ADR-2 identity | Keycloak for development; production IdP from spike S2 | Same |
| ADR-3 approval channel | Dashboard queue first | Same |
| ADR-4 tenancy | Shared multi-tenant with row-level security | Same; `docs/data-model.md` |
| ADR-5 stdio | Managed wrapper | Same |
| ADR-6 policy language | Rego on OPA | Same |
| ADR-7 anchoring | Object-lock storage in a separate account | Same |

## 10. Prioritised plan

The prioritised implementation plan is `docs/roadmap.md`; the gap-by-gap action plan is `docs/reviewgap.md` Section 6. In this assessment's terms the order is:
1. Decide ADR-3, ADR-4, ADR-6 and name owners and reviewers (Phase 0 sign-off).
2. Specify the build-level artefacts: data model, API, authorization policy examples (before Phase 1).
3. Run spikes S1 to S6 and complete verification of unverified claims (before Phase 2).
4. Build the MVP controls that prove the core invariants: pinning, deny by default, SSRF guard, audit chain (Phase 1).
5. Add runtime protection with measured latency and shadow-mode detector tuning (Phase 2).

## 11. Acceptance criteria for this assessment

- Every finding in Sections 2 to 8 is traceable to a requirement, control, test, decision record or an explicit statement that it is out of scope (done in the tables above).
- The assessment is reviewed by security architecture, compliance and operations, and the review is recorded in `docs/governance.md` (not yet done).
- It is refreshed when the MCP specification revision, a major ADR or the threat list changes.

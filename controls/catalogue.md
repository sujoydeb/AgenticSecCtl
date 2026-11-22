# Control Catalogue: AgenticSecCtl

> **Generated file. Do not edit.** Source: `controls/catalogue.yaml`. Regenerate with `python3 -I scripts/build_catalogue_md.py controls/catalogue.yaml controls/catalogue.md`.

| | |
|---|---|
| Version | 0.1 |
| Status | Draft. Every control is specified; none is implemented. Numeric parameters come from the functional spec; where the spec gives no value the entry says to be set. |
| Depends on | Plan/functional-spec.md v0.3, Plan/architecture.md v0.2, Plan/threat-model.md v0.2, docs/testing/cases.md v0.2, docs/runbooks/operational-runbook.md v0.2, compliance/compliance-matrix.md v0.2 |
| Satisfies | FR-COMP-1 (control catalogue with description, owner, type and component). Framework mappings live in compliance/compliance-matrix.md and are not repeated here. |

## How to read this catalogue

A control is a platform capability that reduces a named threat. Each entry says how the control works step by step, what it contributes to prevention, detection, response and recovery, how it fails, where it produces false positives and false negatives, how it can be bypassed, and what risk remains. Owners are roles, not people. Status is specified for every control.

**Enforcement classes**

- deterministic: the decision is made by fixed rules or checks that give the same result for the same input; this is the only class allowed to enforce a high-impact decision alone.
- human: a person decides, with deterministic gates around the decision (who may decide, what exactly is being approved, expiry, audit).
- advisory: produces signals or reports; never the sole control for a high-impact decision.
- hybrid: a deterministic part enforces and an advisory or human part adds judgement; the deterministic part alone must keep the system safe.

**Out of scope for this catalogue**

- Business-process controls outside the platform (risk classification of AI systems, data protection impact assessments, regulatory reporting decisions, model validation); see compliance/compliance-matrix.md Section 6.
- Controls inside MCP servers and agent frameworks that the platform cannot observe; the platform reports these gaps through CTL-26.
- Physical and HR controls.

## Summary

| ID | Control | Type | Enforcement | Component | Phase | Owner (role) |
|---|---|---|---|---|---|---|
| [CTL-01](#ctl-01) | Inventory and registration of agents, servers and tools with owner, environment, criticality | P, D | deterministic | Registry/API | P1 | Security engineering |
| [CTL-02](#ctl-02) | Tool scanning with reproducible scoring; approval with separation of duties and dual-control override | P, D | hybrid | Scanner, Registry | P1 | Security engineering |
| [CTL-03](#ctl-03) | Definition pinning (canonical hash) and drift quarantine | P, D, R | deterministic | Gateway, Registry | P1/P2 | Security engineering |
| [CTL-04](#ctl-04) | Agent identity and credential lifecycle (unique identity, rotation, revocation, deny on revocation-lookup failure) | P, R | deterministic | Identity/broker | P1/P2 | Identity and access team |
| [CTL-05](#ctl-05) | Authentication hardening: audience/scope validation, sender-constrained tokens, no token passthrough, session binding, server identity validation, secret redaction | P, D | deterministic | Gateway, broker | P1/P2 | Identity and access team |
| [CTL-06](#ctl-06) | Least-privilege authorization, deny by default, action classes, agent→server allowlists, unused-permission and escalation reporting | P, D | deterministic | PDP, Gateway | P1/P2/P3 | Security engineering |
| [CTL-07](#ctl-07) | Just-in-time access and human approval for high-impact actions bound to argument hash | P | human | PDP, API | P2 | Business owner and approver pool |
| [CTL-08](#ctl-08) | SSRF protection and egress allowlisting | P, D | deterministic | Egress proxy, Scanner | P1/P2 | Platform security |
| [CTL-09](#ctl-09) | Response inspection for injection, untrusted labelling, taint rule | P, D | hybrid | Gateway, Inspection | P2 | Security engineering |
| [CTL-10](#ctl-10) | Data loss prevention on requests and responses; tenant isolation | P, D | hybrid | Gateway, DLP | P2 | Data protection / security engineering |
| [CTL-11](#ctl-11) | Argument guards, schema validation, execution sandboxing | P | deterministic | Gateway, platform | P2/P4 | Platform security |
| [CTL-12](#ctl-12) | Autonomy limits, budgets, loop detection, kill switch with different-approver resume | P, D, R | deterministic | Gateway, API | P2 | Security engineering |
| [CTL-13](#ctl-13) | Tamper-evident audit: hash chain, external anchoring, reproducible decisions, deny-high-impact when audit cannot record | D | deterministic | Audit service | P1/P2 | Security operations / audit liaison |
| [CTL-14](#ctl-14) | Security monitoring and alerting; platform observability | D | advisory | Analytics, observability | P2/P4 | Security operations |
| [CTL-15](#ctl-15) | Incident detection, containment, evidence preservation, reporting | R, V | human | Incident manager | P2/P3/P4 | Incident commander / security operations |
| [CTL-16](#ctl-16) | Policy lifecycle: source control and review, signed bundles, shadow mode | P | hybrid | PDP, CI | P1/P3 | Security engineering |
| [CTL-17](#ctl-17) | Supply-chain security: SBOM, vulnerability scanning, signing/provenance, third-party intake | P, D | deterministic | CI, scanner, admission | P3/P4 | Platform security |
| [CTL-18](#ctl-18) | MCP lifecycle controls: version allowlist, capability limits, sampling/elicitation default-deny, roots, notifications | P | deterministic | Gateway | P2 | Security engineering |
| [CTL-19](#ctl-19) | Memory and RAG integrity: attributed writes, provenance labels, partitions, rollback | P, D, V | hybrid | Memory tools, Inspection | P4 | Security engineering |
| [CTL-20](#ctl-20) | Inter-agent security: authenticated delegation, no privilege amplification, cycle/depth limits | P | deterministic | Gateway, PDP | P4 | Security engineering |
| [CTL-21](#ctl-21) | Model registry and endpoint protection: approved model pinning, substitution detection, quotas | P, D | deterministic | Registry, Gateway | P3/P4 | AI governance / model owner |
| [CTL-22](#ctl-22) | Multi-tenancy, data residency and retention | P | deterministic | Platform | P2/P5 | Data protection / platform ops |
| [CTL-23](#ctl-23) | Separation of duties, privileged and break-glass access | P, D | deterministic | API, IdP | P1/P2 | Security administration |
| [CTL-24](#ctl-24) | Resilience: fail-closed behaviour, HA, backup, DR testing | P, V | deterministic | Platform | P1/P5 | Platform operations |
| [CTL-25](#ctl-25) | Compliance evidence generation and framework mapping governance | D | hybrid | Compliance engine | P3 | Compliance liaison |
| [CTL-26](#ctl-26) | Discovery and coverage reporting (known gaps) | D | advisory | Discovery | P2/P3 | Security engineering |
| [CTL-27](#ctl-27) | Secure development and change management for the platform | P | hybrid | CI/CD, process | P1 onward | Engineering management / platform security |

## CTL-01

### Inventory and registration of agents, servers and tools with owner, environment, criticality

**Objective.** Ensure every agent, server and tool that can act is known, owned and classified, and that unknown ones are denied.

**Enforcement:** deterministic · **Type:** P, D · **Component:** Registry/API · **Phase:** P1 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. An owner registers an agent (owner, environment, criticality, model reference) or a server (URL, namespace, transport, owner, expected egress destinations).
2. The server URL passes the SSRF guard (CTL-08) before any connection is made.
3. A person other than the requester approves agent registration (SoD-1, FR-ID-2).
4. Servers and tools receive unique IDs; tools are addressed as namespace__tool; identical tool names on different servers raise a duplicate-name finding and are never routed implicitly.
5. The gateway consults the registry cache; an unregistered agent or server is denied.

**Prevent**

- Calls from unregistered agents or to unregistered servers are denied.
- Ambiguous tool names cannot be routed.

**Detect**

- Duplicate-name findings at registration; assets without an owner appear in reports.

**Respond**

- Mark an asset retired or quarantined; revoke its identity (CTL-04).

**Recover**

- Re-registration with a new approval after remediation.

**Parameters**

- Namespace separator: double underscore (architecture and spec FR-INV-2).
- Registry cache TTL at the gateway: at most 60 s.

**Failure behaviour.** Registry unreachable and cache expired: deny.

**False positives**

- A legitimate new development server is blocked until registered.
- Generic tool names shared by design raise duplicate-name findings.

**False negatives**

- Assets that never pass through the gateway are not seen unless discovery (CTL-26) finds them.

**Bypass scenarios**

- Local stdio servers, IDE-embedded agents and direct SaaS connectors that skip the gateway.
- Agent frameworks that drop namespaces on the client side.

**Residual risk.** Unmanaged endpoints remain outside enforcement and are reported only (threat X2). Accepted until owners sign off.

**Requirements:** FR-INV-1..4, FR-ID-1..2

**Threats:** C, F, X2

**Tests:** TC-C1, TC-C3, TC-F1

**Depends on controls:** CTL-08, CTL-23

**Evidence required**

- Inventory export with owners and criticality.
- Registration approvals showing requester and approver.
- Unregistered-asset and duplicate-name reports.

**Metrics (KPI/KRI)**

- Assets without an owner (target 0).
- Denials for unregistered agent or server per day.
- Share of observed tool calls that go through registered agent-server pairs.

## CTL-02

### Tool scanning with reproducible scoring; approval with separation of duties and dual-control override

**Objective.** Stop poisoned or unsafe tool definitions from being approved, with evidence and a reproducible score.

**Enforcement:** hybrid · **Type:** P, D · **Component:** Scanner, Registry · **Phase:** P1 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. A hardened importer fetches tools/list from the registered server with timeouts, size and depth caps, no redirects by default, in an unprivileged isolated worker.
2. Definitions are normalised (Unicode NFC, invisible and bidirectional characters flagged, common encodings decoded for analysis only).
3. Deterministic rules produce findings with rule ID, severity, location, evidence excerpt and confidence.
4. Score = min(100, sum of rule weight x confidence); weights Critical 40, High 20, Medium 8, Low 2; the rule-set version is stored with the scan.
5. An optional classifier can only raise severity; it never lowers a deterministic finding and never approves.
6. A reviewer who is not the owner approves; a Critical finding needs two distinct approvers and a justification with expiry.
7. On a rule-set update approved tools are re-scanned; a Critical finding quarantines the tool and notifies, lower severities create review items.

**Prevent**

- Tools with Critical findings cannot be approved by one person.

**Detect**

- Hidden or override instructions, credential requests, URLs and IPs, encoded blobs, tool-chaining instructions, schema anomalies.

**Respond**

- Reject the tool or quarantine it (CTL-03); notify owner and approvers.

**Recover**

- Owner fixes the definition; a new version is scanned and approved.

**Parameters**

- Severity weights: Critical 40, High 20, Medium 8, Low 2.
- Override: two distinct approvers (SoD-2).
- Importer limits (timeout, size, depth): to be set.

**Failure behaviour.** Scanner unavailable: scans queue and nothing new can be approved; live calls on already approved tools are unaffected.

**False positives**

- Legitimate descriptions that contain words like ignore or documentation URLs.
- Benign encoded strings in examples.

**False negatives**

- Paraphrased, multilingual or split-across-fields instructions that rules do not match.
- A tool that is benign at review and changes later (see CTL-03).

**Bypass scenarios**

- Instruction text phrased to avoid the rule set.
- Collusion between two approvers.

**Residual risk.** Novel phrasing evades deterministic rules and the classifier is advisory, so the control reduces but does not remove tool poisoning (threat A). Detector quality budgets are in spec Section 10.

**Requirements:** FR-SCAN-1..4, FR-SCAN-6, FR-SCAN-9, SoD-1, SoD-2

**Threats:** A, X1, X6

**Tests:** TC-A1..A5, TC-E4, TC-Z2

**Depends on controls:** CTL-08, CTL-23

**Evidence required**

- Scan reports with rule-set version, findings and evidence.
- Approval and override records with approver identities.
- Precision and recall results on the labelled corpus.

**Metrics (KPI/KRI)**

- Recall and precision on the benchmark corpus (targets: 95 percent and 90 percent).
- Overrides per month and their age.
- Time from registration to decision.

**Unverified claims.** External MCP scanners as advisory signals or corpus sources are unverified (docs/tech-evaluation.md).

## CTL-03

### Definition pinning (canonical hash) and drift quarantine

**Objective.** Make sure agents only use the exact tool definition that was approved, and block it the moment it changes.

**Enforcement:** deterministic · **Type:** P, D, R · **Component:** Gateway, Registry · **Phase:** P1/P2 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. On approval, store the canonical JSON (RFC 8785, Unicode NFC) of server ID, name, description, input schema, output schema and annotations, and its SHA-256; approved versions are immutable (database trigger).
2. The gateway recomputes the hash on every tools/list, on list_changed notifications, on a scheduled poll and at call time against a definition cached for at most 60 s.
3. On mismatch the tool is set to quarantined, removed from lists, calls are denied, a finding is raised and approvers are notified with a field-level diff.
4. Re-approval creates a new immutable version; history is kept.

**Prevent**

- Calls to a changed definition are denied before the server is contacted.

**Detect**

- Hash mismatch events with old and new hash and the changed field.
- Response shape and size deviations from a baseline (Phase 4).

**Respond**

- Automatic quarantine; notification; diff view for review.

**Recover**

- Re-scan and approve a new version, or reject.

**Parameters**

- Definition cache TTL for call-time check: 60 s default.
- Quarantine propagation to gateway caches: within 5 s.

**Failure behaviour.** Registry unreachable: the gateway keeps denying hash mismatches from its local approved copy; after the cache expires all calls are denied.

**False positives**

- Benign server releases that change descriptions or schemas quarantine many tools at once (quarantine storm).

**False negatives**

- Behaviour that changes while the definition stays identical, including per-user or time-conditional behaviour.

**Bypass scenarios**

- Exploiting the cache window (bounded by the call-time check).
- Malicious behaviour approved from the start.

**Residual risk.** Hashing detects change, not malice; unchanged definitions can still behave badly (threat B, X7). Compensating controls are CTL-09 and behaviour baselines.

**Requirements:** FR-DRIFT-1..7

**Threats:** A, B, X7

**Tests:** TC-B1..B4, TC-Z3

**Depends on controls:** CTL-13

**Evidence required**

- Version history with hashes.
- Drift events with diffs and quarantine records.
- Race-test results.

**Metrics (KPI/KRI)**

- Time from change to quarantine.
- Calls to quarantined tools that succeeded (target 0).
- Quarantines per week and share resolved as benign.

## CTL-04

### Agent identity and credential lifecycle (unique identity, rotation, revocation, deny on revocation-lookup failure)

**Objective.** Give every agent its own revocable identity so misuse is attributable and containable.

**Enforcement:** deterministic · **Type:** P, R · **Component:** Identity/broker · **Phase:** P1/P2 · **Owner (role):** Identity and access team · **Status:** specified

**How it works**

1. Each agent gets a unique identity and OAuth client; shared credentials are not allowed.
2. Registration needs an owner and an approver who is not the requester.
3. Credentials are short-lived and rotated; the revocation list is distributed to gateways.
4. On a suspected compromise the broker and IdP revoke tokens and clients; gateways deny revoked identities.
5. If the revocation list or service cannot be consulted, the gateway denies.

**Prevent**

- Unregistered or revoked identities cannot call tools.

**Detect**

- New client registrations and credential use from unexpected places are alerted.

**Respond**

- Immediate revocation and suspension of the agent.

**Recover**

- New credentials issued under separation of duties.

**Parameters**

- Access token lifetime: 10 minutes or less by default (FR-AUTHN-2).
- Rotation interval: to be set.

**Failure behaviour.** Revocation lookup unavailable: deny (FR-ID-7).

**False positives**

- Deny after a transient revocation-service failure interrupts valid agents.

**False negatives**

- A compromised but legitimately registered agent is not detected by identity alone.

**Bypass scenarios**

- Stolen token used inside its lifetime when sender binding is unavailable.

**Residual risk.** Compromise of a legitimate agent identity remains possible and is limited by least privilege and monitoring (threat F).

**Requirements:** FR-ID-1..3, FR-ID-7

**Threats:** F, G

**Tests:** TC-F1, TC-F2, TC-G1

**Depends on controls:** CTL-23

**Evidence required**

- Client registry with owners.
- Rotation and revocation logs.

**Metrics (KPI/KRI)**

- Time to revoke after decision.
- Credentials older than the rotation interval.

**Unverified claims.** Support for DPoP, mTLS binding and token exchange depends on the chosen IdP and is unverified.

## CTL-05

### Authentication hardening: audience/scope validation, sender-constrained tokens, no token passthrough, session binding, server identity validation, secret redaction

**Objective.** Stop stolen, replayed or mis-targeted credentials and confused-deputy use from working.

**Enforcement:** deterministic · **Type:** P, D · **Component:** Gateway, broker · **Phase:** P1/P2 · **Owner (role):** Identity and access team · **Status:** specified

**How it works**

1. On every request the gateway validates signature, issuer, expiry, audience (its own resource identifier) and scope.
2. Where the IdP supports it, tokens are bound to the sender (DPoP or mTLS) and replay from another client fails.
3. The gateway never forwards client tokens to servers; it obtains audience-bound upstream credentials by token exchange or from the secrets broker.
4. Session IDs are unguessable, expire and are bound to the authenticated client; reuse by another client is rejected.
5. The server certificate or JWKS is checked against the pin in the registry before data is sent.
6. Logs, traces, errors and the UI redact tokens and secrets.

**Prevent**

- Tokens for another audience, expired or forged tokens, and session reuse by a different client.

**Detect**

- Authentication failures by category, sender mismatch and session-client mismatch alerts.

**Respond**

- Revoke client, suspend session (CTL-04, CTL-12).

**Recover**

- Rotate credentials; re-establish sessions.

**Parameters**

- Access token lifetime: 10 minutes or less by default.

**Failure behaviour.** IdP key set unreachable: cached keys are used until they expire, then all calls are denied.

**False positives**

- Valid clients rejected after clock skew or key rotation.

**False negatives**

- Fallback mode without sender binding allows replay until revocation or expiry.

**Bypass scenarios**

- Long-lived tokens configured by owners.
- Secrets that reach logs through formats the redactor does not recognise.

**Residual risk.** In fallback mode a stolen token is usable inside its lifetime (threat G); the test record states the mode used.

**Requirements:** FR-AUTHN-1..6

**Threats:** C, F, G

**Tests:** TC-C2, TC-F2, TC-G1..G5

**Depends on controls:** CTL-04

**Evidence required**

- Token validation configuration.
- Authentication failure logs without secret values.
- Redaction test results and the sender-binding mode in use.

**Metrics (KPI/KRI)**

- Authentication failures by category.
- Share of tokens sender-constrained.
- Secret-in-log findings (target 0).

**Unverified claims.** MCP authorization requirements, DPoP/mTLS support and token exchange are unverified against the current MCP specification and IdP documentation.

## CTL-06

### Least-privilege authorization, deny by default, action classes, agent→server allowlists, unused-permission and escalation reporting

**Objective.** Limit each agent to the specific tools, action classes and resources it needs, and notice when that drifts.

**Enforcement:** deterministic · **Type:** P, D · **Component:** PDP, Gateway · **Phase:** P1/P2/P3 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. The gateway sends the PDP agent, tool, action class (read, write, execute, delete), resource, an arguments digest and context such as taint and grants.
2. OPA evaluates signed policy and registry data and returns allow or deny plus obligations; the default is deny.
3. Tool annotations are never used as inputs; the action class comes from the registry, set at approval.
4. An agent-to-server allowlist is enforced.
5. Reports list permissions unused for 30 days, permissions broader than observed use, and changes made outside an approved change.

**Prevent**

- Calls outside granted tool, action class or resource are denied.

**Detect**

- Unused and excessive permissions; unapproved permission changes.

**Respond**

- Remove the grant or allow rule; suspend the agent if abused.

**Recover**

- Re-grant under review with a TTL where appropriate.

**Parameters**

- Unused-permission window: 30 days default.
- Decision cache TTL: short, keyed on policy hash and input digest; value to be set.

**Failure behaviour.** PDP or policy bundle unavailable or stale: deny. A tenant may allowlist specific read-only low-risk tools for fail-open, always flagged in the audit log.

**False positives**

- Legitimate rare tasks denied because the grant was too narrow.

**False negatives**

- A wrong action-class mapping, such as a read tool that actually writes, lets a call through.

**Bypass scenarios**

- Wildcard resource patterns written by owners.
- Argument-level abuse inside a permitted tool.

**Residual risk.** Quality of the tool-to-action-class mapping depends on approvers (threat E); periodic recertification is required.

**Requirements:** FR-AUTHZ-1..3, FR-AUTHZ-6..8

**Threats:** C, E

**Tests:** TC-E1, TC-E2, TC-C3, TC-Z5

**Depends on controls:** CTL-13, CTL-16

**Evidence required**

- Policy bundles with hashes.
- Decision logs with policy hash and input digest.
- Permission review records.

**Metrics (KPI/KRI)**

- Deny rate by reason.
- Permissions unused over 30 days.
- Fail-open decisions (target near 0).

**Unverified claims.** OPA performance with realistic policy data is unmeasured (spike S3).

## CTL-07

### Just-in-time access and human approval for high-impact actions bound to argument hash

**Objective.** Make sure risky actions happen only with a specific, current human decision.

**Enforcement:** human · **Type:** P · **Component:** PDP, API · **Phase:** P2 · **Owner (role):** Business owner and approver pool · **Status:** specified

**How it works**

1. A requester asks for access with tool, action, resource, TTL and reason; an approver who is not the requester approves; the grant expires automatically.
2. Policy marks high-impact actions: any delete; write or execute on resources tagged critical; sending confidential data outside; financial transactions; actions after untrusted content followed a sensitive read.
3. For a high-impact call the PDP returns an approval obligation; the gateway holds the call and creates a task showing the exact arguments.
4. Approval is bound to the hash of those arguments; a changed argument needs a new approval; timeout means deny.

**Prevent**

- High-impact actions without a matching approval are denied.

**Detect**

- Approval request volume and approval of unusual requests.

**Respond**

- Revoke the grant; suspend the agent.

**Recover**

- Reverse the action through the owning system.

**Parameters**

- JIT TTL: mandatory, value per request.
- Approval timeout: to be set.

**Failure behaviour.** Approval service unavailable or timeout: deny.

**False positives**

- Approvals required for actions the business considers routine.

**False negatives**

- Harmful actions not classified as high-impact are not gated.

**Bypass scenarios**

- Approver fatigue and rubber-stamping.
- Many small actions under a threshold.

**Residual risk.** Depends on the quality of the high-impact definition and approver attention (threats D, K, E).

**Requirements:** FR-AUTHZ-4..5, FR-AUTO-3

**Threats:** D, E, K

**Tests:** TC-E3, TC-D4, TC-K3

**Depends on controls:** CTL-06, CTL-13, CTL-23

**Evidence required**

- Grant and approval records with approver and arguments hash.
- Timeout and denial records.

**Metrics (KPI/KRI)**

- Approval latency.
- Approval rate and share approved in under 10 seconds (rubber-stamp indicator).
- Expired grants.

## CTL-08

### SSRF protection and egress allowlisting

**Objective.** Stop the platform and MCP servers from being used to reach metadata services, internal systems or arbitrary hosts.

**Enforcement:** deterministic · **Type:** P, D · **Component:** Egress proxy, Scanner · **Phase:** P1/P2 · **Owner (role):** Platform security · **Status:** specified

**How it works**

1. Every outbound connection by the platform (registration, import, discovery, health check, proxying) goes through the guard.
2. The guard normalises the host (decimal, octal, hex, IPv6 forms, userinfo tricks), resolves DNS and validates every returned address against the blocklist: loopback, link-local including 169.254.169.254, RFC 1918, unique-local, multicast, unspecified, IPv4-mapped IPv6, metadata hostnames.
3. It connects to the validated IP (resolve then pin); redirects are off by default and, if enabled, each hop is re-validated, at most 3.
4. Server pods can reach only the destinations in their registry allowlist, enforced by network policy or egress proxy outside the gateway process.
5. Exceptions are explicit per-server entries with owner approval and expiry.

**Prevent**

- Connections to blocked ranges and unlisted destinations.

**Detect**

- Blocked-connection events; bursts of probing.

**Respond**

- Quarantine the registering server; isolate a pod that reached internal addresses; rotate credentials that could have been exposed.

**Recover**

- Remove the exception, fix the allowlist, re-approve the server.

**Parameters**

- Maximum redirect hops when enabled: 3.
- Exception expiry: to be set.

**Failure behaviour.** Guard cannot resolve or validate: connection refused.

**False positives**

- Legitimate internal servers blocked until an exception is approved.

**False negatives**

- Server-side SSRF inside third-party server code is limited only by network egress policy.

**Bypass scenarios**

- Parser differences between the guard and the HTTP client library.
- Over-broad allowlist exceptions.

**Residual risk.** Misconfigured exceptions and server-internal request forgery remain (threat H); cloud metadata hardening per cloud is needed.

**Requirements:** FR-SSRF-1..5, FR-RT-7

**Threats:** H, I

**Tests:** TC-H1..H4, TC-I4, TC-X2

**Depends on controls:** CTL-13

**Evidence required**

- Guard configuration and blocklist.
- Blocked-connection logs.
- Network policy exports and exception approvals.

**Metrics (KPI/KRI)**

- Blocked connections per day.
- Active exceptions and their age.
- Direct connections that bypassed the gateway (target 0).

**Unverified claims.** Cloud-specific metadata hardening (IMDSv2 enforcement, pod-level blocking) is unverified per cloud.

## CTL-09

### Response inspection for injection, untrusted labelling, taint rule

**Objective.** Prevent instructions hidden in tool responses or retrieved content from causing unapproved actions or data egress.

**Enforcement:** hybrid · **Type:** P, D · **Component:** Gateway, Inspection · **Phase:** P2 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. All tool output is labelled untrusted and delivered in a structure separate from system and developer instructions; a response can never change system-level instructions.
2. Tier 1 deterministic parsing of text, HTML, JSON and markdown looks for hidden elements, comments, markdown image or link exfiltration patterns, and instructions to run other tools.
3. Tier 2 and 3 classifiers add advisory signals with confidence.
4. Policy maps signals to an action: allow with label, redact, block, or quarantine the tool.
5. Taint rule: after an untrusted read of sensitive data, write, execute and external-send tools are blocked in that session until approved.

**Prevent**

- Tainted sessions cannot send data out or act without approval.
- Neutralised markup removes common exfiltration channels.

**Detect**

- Injection signals with element locations.

**Respond**

- Block the response, suspend the session, quarantine the carrier tool.

**Recover**

- Remove or sanitise the content at source; resume the agent.

**Parameters**

- Tier 1 inline budget: under 5 ms for typical payloads.
- Inline classifier: p95 at most 150 ms or run asynchronously (NFR-2).
- False-block rate in shadow mode: at most 0.5 percent of benign calls (spec Section 10).

**Failure behaviour.** Tier 1 failure on a high-impact path: deny. Advisory tiers unavailable: continue with Tier 1 and taint rules.

**False positives**

- Benign text with imperative language flagged or redacted.

**False negatives**

- Paraphrased, multilingual, image-embedded or split payloads.

**Bypass scenarios**

- Visible-text injections that read like normal content.
- Sensitive data not tagged, so taint is not set.

**Residual risk.** Detection is probabilistic, so safety rests on CTL-07, CTL-08 and the taint rule (threat D, I). Residual risk is medium to high and cannot be removed.

**Requirements:** FR-RT-4..5, FR-RT-9, FR-RT-11

**Threats:** A, D, I

**Tests:** TC-D1..D5

**Depends on controls:** CTL-07, CTL-08, CTL-13

**Evidence required**

- Detector configuration and versions.
- Shadow-mode results before enforcement.
- Signal logs and red-team results.

**Metrics (KPI/KRI)**

- Signals per 1,000 calls.
- Recall on the injection test set.
- False-block rate.

**Unverified claims.** Candidate classifiers and their licences are unverified (docs/tech-evaluation.md).

## CTL-10

### Data loss prevention on requests and responses; tenant isolation

**Objective.** Keep personal, financial, secret and tenant-private data from leaving through tool traffic or reaching the wrong tenant.

**Enforcement:** hybrid · **Type:** P, D · **Component:** Gateway, DLP · **Phase:** P2 · **Owner (role):** Data protection / security engineering · **Status:** specified

**How it works**

1. Requests and responses are scanned for PII, Luhn-validated card numbers and other financial identifiers, secrets and keys, source-code markers and tenant data tags.
2. Per-tenant policy maps matches to redact, block or alert, depending on agent clearance.
3. Every request, cache entry, log and evidence record carries a tenant ID; database row-level security enforces separation even if application filters fail.
4. Audit stores digests and redacted excerpts; raw evidence goes to an encrypted vault.

**Prevent**

- Redaction or blocking of matched data; cross-tenant reads fail.

**Detect**

- Match events by entity type and count.

**Respond**

- Kill switch for the agent, block server egress, start the exfiltration playbook.

**Recover**

- Rotate exposed credentials; close the channel.

**Parameters**

- Redaction and block actions per tenant policy: to be set.
- Precision target for checksum-based identifiers: at least 99 percent.

**Failure behaviour.** DLP engine failure on a high-impact path: deny. On low-impact paths policy decides, default deny.

**False positives**

- Order numbers or test data that look like card numbers; free-text PII over-matching.

**False negatives**

- Free-text PII recall is limited; encoded, chunked or steganographic leakage.

**Bypass scenarios**

- Leakage through legitimate tool parameters in small pieces over time.

**Residual risk.** Low-and-slow and encoded exfiltration remain possible (threat I); free-text PII needs per-tenant tuning.

**Requirements:** FR-RT-6, FR-RT-8, FR-AUD-3

**Threats:** I

**Tests:** TC-I1..I3, TC-G5

**Depends on controls:** CTL-08, CTL-22

**Evidence required**

- DLP policies and tuning records.
- Match logs.
- Cross-tenant negative test results.

**Metrics (KPI/KRI)**

- Matches by entity type.
- Blocked versus redacted versus alerted.
- Cross-tenant access attempts (target 0 successful).

**Unverified claims.** Presidio-style engines and their licences and performance are unverified (docs/tech-evaluation.md).

## CTL-11

### Argument guards, schema validation, execution sandboxing

**Objective.** Stop malicious arguments from turning tool calls into command, SQL or path attacks, and contain code execution.

**Enforcement:** deterministic · **Type:** P · **Component:** Gateway, platform · **Phase:** P2/P4 · **Owner (role):** Platform security · **Status:** specified

**How it works**

1. Arguments are validated against the approved input schema; unknown fields are rejected.
2. Parameters declared as path, command or query are checked for traversal sequences, shell and SQL metacharacters and absolute paths outside approved roots; URL parameters pass the SSRF guard.
3. Servers that execute code run non-root with a read-only filesystem, no privileged capabilities, resource limits and a sandboxed runtime.
4. File upload tools enforce type, size and malware checks.

**Prevent**

- Calls with illegal arguments are denied before reaching the server.
- Sandbox limits the impact of any execution that gets through.

**Detect**

- Argument-guard events; runtime security alerts from pods.

**Respond**

- Quarantine the tool; isolate the pod and node.

**Recover**

- Patch, tighten schema, rebuild nodes if escape is suspected.

**Parameters**

- Sandbox profile and limits: to be set per server class.

**Failure behaviour.** Guard error: deny.

**False positives**

- Legitimate arguments containing special characters rejected.

**False negatives**

- Parameters not declared as path, SQL or command but used as such by the server.

**Bypass scenarios**

- Server-side bugs the gateway cannot see; symlink handling inside the server.

**Residual risk.** Server-side vulnerabilities are outside platform control (threat O); sandboxing bounds impact.

**Requirements:** FR-RT-2..3, FR-EXEC-1..2

**Threats:** O, H

**Tests:** TC-O1..O3, TC-Z1

**Depends on controls:** CTL-03, CTL-08

**Evidence required**

- Guard rules and schema validation logs.
- Sandbox and pod security profiles.

**Metrics (KPI/KRI)**

- Guard denials by type.
- Servers running outside the sandbox profile (target 0 for execution tools).

**Unverified claims.** Sandboxed runtimes (gVisor, Kata) availability and compatibility per cloud are unverified.

## CTL-12

### Autonomy limits, budgets, loop detection, kill switch with different-approver resume

**Objective.** Bound what an agent can do on its own in calls, time, cost and delegation, and allow immediate suspension.

**Enforcement:** deterministic · **Type:** P, D, R · **Component:** Gateway, API · **Phase:** P2 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. Per-agent and per-session counters cover tool calls, distinct tools, delegation depth, wall-clock time and cost or tokens.
2. Repeating call sequences are detected and the session is suspended.
3. Financial or irreversible transactions need approval unless policy allows a bounded amount to an allowlisted counterparty.
4. A kill switch suspends an agent or all agents of a tenant within 5 s.
5. Resuming needs an approver other than the person who suspended, unless an emergency policy applies; both actions are audited.

**Prevent**

- Calls beyond limits are denied.

**Detect**

- Limit events, loops, approval floods.

**Respond**

- Session suspension; kill switch.

**Recover**

- Resume by a different approver after the cause is fixed.

**Parameters**

- Kill switch effect: within 5 s.
- Delegation depth: 3 by default.
- Loop detection threshold: 50 calls in the test setting; production value to be set.
- Per-session call, time and cost limits: to be set per agent.

**Failure behaviour.** Limit store unavailable: deny new high-impact calls; low-impact policy decides, default deny.

**False positives**

- Legitimate long-running jobs suspended.

**False negatives**

- Slow loops under thresholds; many agents each under budget.

**Bypass scenarios**

- Spreading load across agents or tenants.

**Residual risk.** Distributed or slow abuse stays under per-agent limits (threat K); per-tenant caps and analytics reduce but do not remove it.

**Requirements:** FR-AUTO-1..5, FR-ID-5, FR-RT-10

**Threats:** K, M

**Tests:** TC-K1..K3, TC-M1, TC-Z4

**Depends on controls:** CTL-13, CTL-23

**Evidence required**

- Limit configuration by agent.
- Suspension and resume records with approvers.

**Metrics (KPI/KRI)**

- Limit events per day.
- Time from kill command to effect.
- Suspended agents older than one day.

## CTL-13

### Tamper-evident audit: hash chain, external anchoring, reproducible decisions, deny-high-impact when audit cannot record

**Objective.** Make every decision and administrative action recorded, ordered, reproducible and hard to alter without detection.

**Enforcement:** deterministic · **Type:** D · **Component:** Audit service · **Phase:** P1/P2 · **Owner (role):** Security operations / audit liaison · **Status:** specified

**How it works**

1. Each service writes events through an outbox: actor, subject, decision, policy hash, input digest, timestamp.
2. The audit service chains them: hash_n = SHA-256(hash_n-1 || canonical event n); application database roles are insert-only.
3. Chain heads are anchored on a schedule in object-lock storage or an external timestamping service.
4. A verifier recomputes the chain and compares with anchors; modification, deletion or reordering is reported.
5. Raw payloads are not stored in the table; digests and redacted excerpts only; control characters in untrusted fields are escaped before export.
6. When the gateway buffer is full or the sink is down beyond capacity, high-impact calls are denied.

**Prevent**

- Insert-only roles block ordinary tampering; deny-high-impact stops actions that cannot be recorded.

**Detect**

- Verification failures, sequence gaps, anchor mismatches.

**Respond**

- Audit integrity incident; freeze changes; preserve snapshots.

**Recover**

- Restore from the last verified backup and document the gap; never repair the chain.

**Parameters**

- Anchor interval: to be set.
- Retention: 13 months hot and 7 years cold by default, configurable per tenant.
- Buffer capacity: to be set.

**Failure behaviour.** Audit sink down: buffer locally; when full deny high-impact calls and keep buffering low-impact events until capacity is reached; events are never silently dropped.

**False positives**

- Verification failure caused by operator restore mistakes.

**False negatives**

- Rewrite of the whole chain before the first anchor.

**Bypass scenarios**

- Privileged database actor rewriting history between anchors.

**Residual risk.** The chain is tamper-evident, not tamper-proof; anchoring narrows but does not close the window (threat X6, X8).

**Requirements:** FR-AUD-1..7

**Threats:** X5, X6, X8

**Tests:** TC-Z6, TC-X5

**Evidence required**

- Chain verification reports and the latest anchor.
- Sample decision replays from policy hash and input digest.

**Metrics (KPI/KRI)**

- Oldest event age in the outbox.
- Time since last successful verification and anchor.
- Gaps found (target 0).

**Unverified claims.** Object-lock support and external timestamping options per cloud are unverified.

## CTL-14

### Security monitoring and alerting; platform observability

**Objective.** Notice abuse and platform problems early through thresholds, baselines and service metrics.

**Enforcement:** advisory · **Type:** D · **Component:** Analytics, observability · **Phase:** P2/P4 · **Owner (role):** Security operations · **Status:** specified

**How it works**

1. Threshold rules run over the audit stream: rate, denied-call ratio, new tools used, off-hours use, new destinations, notification floods.
2. From Phase 4, per-agent baselines score anomalies; alerts carry an explanation.
3. Services emit OpenTelemetry traces, metrics and structured logs with correlation IDs and redaction.
4. Alerts route to on-call by severity.

**Prevent**

- None directly.

**Detect**

- Abuse patterns, SLO breaches, deny-rate shifts.

**Respond**

- Alerts open incidents or trigger runbook steps.

**Recover**

- None directly.

**Parameters**

- Alert thresholds: to be set after baselining.
- Alert budget target: at most 5 reviewed alerts per 100 agents per day.

**Failure behaviour.** Monitoring failure does not change enforcement; it raises its own alert.

**False positives**

- Legitimate bursts and new tool rollouts raise alerts.

**False negatives**

- Low-and-slow behaviour below thresholds.

**Bypass scenarios**

- Staying inside baselines.

**Residual risk.** Alerts are advisory; they do not stop actions.

**Requirements:** FR-BEH-1..2, FR-OBS-1..2

**Threats:** K, P

**Tests:** TC-K1, TC-P4

**Depends on controls:** CTL-13

**Evidence required**

- Alert rules and routing.
- On-call and acknowledgement records.
- SLO reports.

**Metrics (KPI/KRI)**

- Alerts per agent per day.
- Mean time to acknowledge.
- Share of alerts leading to action.

**Unverified claims.** OpenTelemetry GenAI semantic convention maturity is unverified.

## CTL-15

### Incident detection, containment, evidence preservation, reporting

**Objective.** Contain compromised tools, agents or platform parts quickly, preserve evidence and recover safely.

**Enforcement:** human · **Type:** R, V · **Component:** Incident manager · **Phase:** P2/P3/P4 · **Owner (role):** Incident commander / security operations · **Status:** specified

**How it works**

1. Incidents are opened manually or by rules with severity, affected assets, timeline and owner.
2. One action quarantines a tool, server or agent and revokes tokens; the effect applies within 5 s.
3. At containment an evidence snapshot is taken: definitions and hashes, decisions, redacted traffic, scan results, registry state.
4. Playbooks guide investigation, eradication and recovery; recovery requires reapproval by non-owners.
5. A report with timeline, impact, actions and evidence index is exported.

**Prevent**

- Limits spread of an ongoing compromise.

**Detect**

- Classification of alerts into incidents.

**Respond**

- Quarantine, revocation, kill switch, isolation.

**Recover**

- Reapproval, staged restoration, post-incident review.

**Parameters**

- Containment effect: within 5 s.
- Severity response targets: proposals in docs/playbooks.

**Failure behaviour.** Incident service unavailable: containment actions remain available through the API and break-glass path.

**False positives**

- Benign events escalated to incidents.

**False negatives**

- Incidents not recognised from signals.

**Bypass scenarios**

- An attacker who also controls the responder accounts or the control plane.

**Residual risk.** Response quality depends on practice; playbooks are untested until exercised.

**Requirements:** FR-IR-1..5

**Threats:** A, B, D, G, I, X8

**Tests:** TC-X8, TC-Z6

**Depends on controls:** CTL-04, CTL-03, CTL-13, CTL-23

**Evidence required**

- Incident records and timelines.
- Evidence index with chain of custody.
- Post-incident reviews and exercise results.

**Metrics (KPI/KRI)**

- Time to contain.
- Time to preserve evidence.
- Open incidents by age.

**Unverified claims.** SOAR integration options are unverified.

## CTL-16

### Policy lifecycle: source control and review, signed bundles, shadow mode

**Objective.** Ensure policy changes are reviewed, tested, signed and tried in shadow mode before they enforce.

**Enforcement:** hybrid · **Type:** P · **Component:** PDP, CI · **Phase:** P1/P3 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. Policies are written in Rego, kept in source control, unit-tested with opa test in CI and reviewed by a second person.
2. Bundles are signed; gateways accept only signed, current bundles.
3. New policy runs in shadow mode first: decisions are logged beside the enforced policy and compared; every new allow is reviewed.
4. Enforcement is widened gradually; every decision records the bundle hash.

**Prevent**

- Unreviewed or unsigned policy cannot take effect.

**Detect**

- Policy changes outside process (policy.changed event without approval).

**Respond**

- Revert to the previous signed bundle.

**Recover**

- Fix and re-run shadow comparison.

**Parameters**

- Bundle staleness limit: to be set.
- Shadow period before enforcement: to be set.

**Failure behaviour.** Stale, unsigned or invalid bundle: gateways deny.

**False positives**

- Shadow comparison produces noisy differences.

**False negatives**

- Review misses a harmful rule that tests do not cover.

**Bypass scenarios**

- Collusion between author and reviewer.

**Residual risk.** Policy mistakes and insider abuse remain possible (threat X6, E); reviewed history and the audit trail make them detectable.

**Requirements:** FR-POL-1..4

**Threats:** E, X6

**Tests:** TC-X6, TC-Z5

**Depends on controls:** CTL-13, CTL-23

**Evidence required**

- Change history with approvers.
- Bundle signatures and hashes.
- Shadow-mode comparison reports.

**Metrics (KPI/KRI)**

- Policy changes by approver pair.
- Time in shadow mode.
- Rollbacks.

**Unverified claims.** OPA bundle signing details and Cedar as an alternative are unverified.

## CTL-17

### Supply-chain security: SBOM, vulnerability scanning, signing/provenance, third-party intake

**Objective.** Keep malicious or vulnerable packages, images, models and plugins out of the platform and the server fleet.

**Enforcement:** deterministic · **Type:** P, D · **Component:** CI, scanner, admission · **Phase:** P3/P4 · **Owner (role):** Platform security · **Status:** specified

**How it works**

1. CI produces an SBOM for each build and scans dependencies and images for known vulnerabilities and secrets.
2. Images are signed and referenced by digest; admission policy admits only signed, pinned images to server namespaces.
3. Package names are checked against allowlists and known popular names for typosquatting.
4. Third-party servers go through intake: SBOM, owner, licence and vulnerability status, before approval.
5. Model artifact provenance is reported when supplied.

**Prevent**

- Unsigned, unpinned or vulnerable artifacts fail the gates.

**Detect**

- New vulnerabilities in deployed SBOMs; unexpected outbound connections.

**Respond**

- Quarantine affected servers; block the digest; rotate credentials.

**Recover**

- Rebuild from signed sources and rescan the fleet.

**Parameters**

- Vulnerability severity that fails a build: to be set.

**Failure behaviour.** Gate failure blocks release and admission; scanners unavailable block release.

**False positives**

- Vulnerability findings in unused code paths.

**False negatives**

- Zero-days and malicious code that passes scans; tampered model weights without provenance.

**Bypass scenarios**

- Compromised signing key; build-system compromise.

**Residual risk.** Unknown vulnerabilities and compromised upstream sources remain (threat L).

**Requirements:** FR-SCAN-5, FR-SUP-1..3, FR-MOD-3, NFR-9

**Threats:** L

**Tests:** TC-L1..L3

**Depends on controls:** CTL-27

**Evidence required**

- SBOMs and scan reports.
- Signature verification and admission logs.
- Third-party intake records.

**Metrics (KPI/KRI)**

- Critical vulnerabilities open beyond SLA.
- Unsigned images found (target 0).
- Servers lacking an intake record.

**Unverified claims.** Tooling (Syft, Grype, Trivy, cosign, SLSA) features, licences and offline behaviour are unverified.

## CTL-18

### MCP lifecycle controls: version allowlist, capability limits, sampling/elicitation default-deny, roots, notifications

**Objective.** Close protocol-level abuse paths that do not depend on tool descriptions.

**Enforcement:** deterministic · **Type:** P · **Component:** Gateway · **Phase:** P2 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. Initialize accepts only allowlisted protocol versions; offered capabilities are limited to what policy allows; unexpected capabilities are flagged.
2. Transport uses TLS 1.2 or higher with Origin and Host validation on HTTP transports; local transports only through the managed wrapper.
3. Resource URIs are validated against allowlists and treated as arguments; resource and prompt content is inspected like responses and prompts are hash-pinned.
4. Sampling and elicitation are denied by default; if enabled per server, requests are budgeted and inspected and credential-like requests are blocked.
5. Roots exposed to a server are limited to approved directories; notifications are rate-limited and list_changed triggers a re-hash.

**Prevent**

- Unsupported versions, unexpected capabilities, sampling and elicitation abuse, root over-exposure.

**Detect**

- Unexpected capability and notification events.

**Respond**

- Disable the capability for the server; quarantine the server.

**Recover**

- Update the compatibility matrix and re-enable after tests.

**Parameters**

- Protocol version allowlist: set from the compatibility matrix.
- Notification rate limit: to be set.

**Failure behaviour.** Unknown or unsupported behaviour: refuse or ignore and log.

**False positives**

- New legitimate capabilities blocked until the allowlist is updated.

**False negatives**

- New protocol surfaces introduced by spec revisions.

**Bypass scenarios**

- SDK implementation differences between gateway and client.

**Residual risk.** The MCP specification evolves; compatibility must be re-tested on each revision (threat P, X3, X4).

**Requirements:** FR-AUTHN-5, FR-DRIFT-2, FR-RT-10

**Threats:** P, X3, X4

**Tests:** TC-P1..P4

**Depends on controls:** CTL-05, CTL-03

**Evidence required**

- Protocol configuration and compatibility matrix.
- Deny and flood-handling logs.

**Metrics (KPI/KRI)**

- Sessions by protocol version.
- Unexpected capability events.

**Unverified claims.** Current MCP specification wording on transports, sampling, elicitation and roots is unverified; see spec Section 4.12.

## CTL-19

### Memory and RAG integrity: attributed writes, provenance labels, partitions, rollback

**Objective.** Keep poisoned content from becoming persistent instructions for agents.

**Enforcement:** hybrid · **Type:** P, D, V · **Component:** Memory tools, Inspection · **Phase:** P4 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. Writes through managed memory and vector-store tools are attributed to agent, source and session and authorized.
2. Entries derived from untrusted content carry a provenance label and are delivered as untrusted data.
3. Retrieved content is inspected like tool responses (CTL-09).
4. Memory is partitioned per agent and tenant; cross-agent reads need an explicit grant.
5. Entries can be rolled back in bulk by source or time window.

**Prevent**

- Unauthorized writes; cross-agent reads.

**Detect**

- Instruction-like content in stored entries; unusual write patterns.

**Respond**

- Restrict affected agents to read-only; disable the ingestion source.

**Recover**

- Rollback by source or window; rebuild embeddings.

**Parameters**

- Retention and rollback window: to be set.

**Failure behaviour.** Attribution or authorization failure on write: deny the write.

**False positives**

- Benign notes containing imperative text flagged.

**False negatives**

- Poison that reads as normal content; writes made outside managed tools.

**Bypass scenarios**

- Direct access to the vector store by agent frameworks.

**Residual risk.** Not covered until Phase 4 and only for managed tools (threat J).

**Requirements:** FR-MEM-1..4

**Threats:** J, M

**Tests:** TC-J1, TC-J2

**Depends on controls:** CTL-09, CTL-06

**Evidence required**

- Write attribution logs.
- Rollback records and retrieval signals.

**Metrics (KPI/KRI)**

- Writes by provenance class.
- Flagged entries.

## CTL-20

### Inter-agent security: authenticated delegation, no privilege amplification, cycle/depth limits

**Objective.** Prevent one agent from gaining power or spreading instructions through delegation.

**Enforcement:** deterministic · **Type:** P · **Component:** Gateway, PDP · **Phase:** P4 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. Agent-to-agent calls go through the gateway and are authenticated and authorized.
2. Each call carries the delegation chain.
3. The effective permission of a sub-agent is the intersection with the delegator's permission for that request.
4. The gateway blocks cycles and chains deeper than the limit.

**Prevent**

- Privilege amplification, circular delegation, unauthorized agent-to-agent calls.

**Detect**

- Unusual delegation graph shapes; delegation denials.

**Respond**

- Suspend agents in the chain; remove delegation permission.

**Recover**

- Review and re-approve delegation rules.

**Parameters**

- Maximum delegation depth: 3 by default.

**Failure behaviour.** Missing or invalid chain: deny.

**False positives**

- Legitimate deep workflows blocked by the depth limit.

**False negatives**

- Cycles that pass through systems outside the gateway.

**Bypass scenarios**

- Direct calls by a high-privilege agent outside the delegation path.

**Residual risk.** Phase 4 capability; agent-to-agent protocols are still evolving (threat M).

**Requirements:** FR-ID-4..6

**Threats:** M, F

**Tests:** TC-M1, TC-M2

**Depends on controls:** CTL-04, CTL-06

**Evidence required**

- Delegation logs with chains.
- Policy tests for intersection logic.

**Metrics (KPI/KRI)**

- Delegation denials.
- Chains at maximum depth.

**Unverified claims.** Agent-to-agent protocol standards and their security models are unverified.

## CTL-21

### Model registry and endpoint protection: approved model pinning, substitution detection, quotas

**Objective.** Detect or stop use of unapproved models and abuse of model endpoints.

**Enforcement:** deterministic · **Type:** P, D · **Component:** Registry, Gateway · **Phase:** P3/P4 · **Owner (role):** AI governance / model owner · **Status:** specified

**How it works**

1. The registry records the approved model identifier, version and endpoint per agent.
2. A mismatch between the registered and the reported model raises an alert and policy may block.
3. Endpoints reached through the platform require authentication, rate limits and quotas.
4. Systematic high-volume query patterns raise alerts.

**Prevent**

- Quotas and authentication limit extraction and denial of service.

**Detect**

- Model substitution; extraction-like query patterns.

**Respond**

- Suspend or rate-limit the identity; pin the model.

**Recover**

- Review outputs produced by an unapproved model with the business owner.

**Parameters**

- Quota values per identity: to be set.

**Failure behaviour.** Quota or registry unavailable: deny new requests to the model route.

**False positives**

- Heavy legitimate users flagged as extraction.

**False negatives**

- Distributed extraction across many identities; endpoints that report a false model identity.

**Bypass scenarios**

- Many identities each under quota.

**Residual risk.** Model-internal attacks are outside the platform (threat N).

**Requirements:** FR-MOD-1..3, FR-RT-10

**Threats:** N

**Tests:** TC-N1, TC-N2

**Depends on controls:** CTL-01

**Evidence required**

- Model registry entries.
- Quota and alert logs.

**Metrics (KPI/KRI)**

- Agents without a registered model.
- Substitution alerts.

## CTL-22

### Multi-tenancy, data residency and retention

**Objective.** Keep tenants separate, keep data in permitted regions, and retain or delete it as policy and law require.

**Enforcement:** deterministic · **Type:** P · **Component:** Platform · **Phase:** P2/P5 · **Owner (role):** Data protection / platform ops · **Status:** specified

**How it works**

1. Every row, cache entry, event and evidence item carries a tenant ID; Postgres row-level security enforces it.
2. Per-tenant policy bundles; per-tenant encryption keys in Phase 5.
3. A tenant data plane can be pinned to a region.
4. Retention classes control deletion by data class; legal hold overrides deletion.

**Prevent**

- Cross-tenant access; storage outside the pinned region; premature deletion under hold.

**Detect**

- Cross-tenant access attempts; retention job failures.

**Respond**

- Suspend the tenant's access to the implicated component.

**Recover**

- Restore from backup within the same region and tenant.

**Parameters**

- Retention: 13 months hot and 7 years cold by default per spec NFR-6.

**Failure behaviour.** Tenant context missing: deny.

**False positives**

- Legitimate shared resources blocked by strict tenant checks.

**False negatives**

- Side channels in shared infrastructure.

**Bypass scenarios**

- Application bug that forgets a tenant filter (limited by row-level security).

**Residual risk.** Shared-infrastructure side channels; residency depends on correct deployment (threat I).

**Requirements:** FR-ADM-2, FR-ADM-4..5, FR-RT-8, NFR-6, NFR-8

**Threats:** I

**Tests:** TC-I3

**Depends on controls:** CTL-13

**Evidence required**

- Tenant configuration and key inventory.
- Retention job reports and legal-hold lists.
- Isolation test results.

**Metrics (KPI/KRI)**

- Cross-tenant test failures (target 0).
- Retention job exceptions.

## CTL-23

### Separation of duties, privileged and break-glass access

**Objective.** Ensure no single person can request and approve their own change, and that privileged access is limited and recorded.

**Enforcement:** deterministic · **Type:** P, D · **Component:** API, IdP · **Phase:** P1/P2 · **Owner (role):** Security administration · **Status:** specified

**How it works**

1. Roles come from the enterprise IdP with MFA; permissions follow the role matrix.
2. The API, not the UI, enforces that requester and approver differ for tool approval, JIT grants, high-impact calls and agent registration.
3. Critical-finding overrides need two approvers and expire.
4. No role can alter or delete audit events through application interfaces.
5. Break-glass accounts are sealed in the secrets manager; each use needs a ticket and a second person; sessions are recorded; credentials are rotated after use; the accounts cannot modify audit records or read raw evidence.

**Prevent**

- Self-approval and single-person overrides; unrecorded privileged access.

**Detect**

- Rejected self-approvals; break-glass use; approval concentration between two people.

**Respond**

- Suspend approval rights of involved accounts; revert policy.

**Recover**

- Re-review decisions; recertify approvers.

**Parameters**

- Override approvers required: 2.
- Access recertification interval: quarterly in the runbook.

**Failure behaviour.** IdP unavailable: no new privileged sessions; break-glass path available under its own controls.

**False positives**

- Small teams struggle to find a second approver.

**False negatives**

- Collusion between two approvers.

**Bypass scenarios**

- Shared credentials or accounts outside the IdP.

**Residual risk.** Collusion and compromised privileged accounts (threat X6, X8).

**Requirements:** SoD-1, SoD-2, SoD-3, FR-ADM-6, FR-UI-7

**Threats:** E, X6, X8

**Tests:** TC-E4, TC-X6, TC-X8

**Depends on controls:** CTL-13

**Evidence required**

- Role bindings and access reviews.
- Break-glass usage records and post-use reviews.

**Metrics (KPI/KRI)**

- Self-approval attempts.
- Break-glass uses.
- Accounts with privileged roles.

## CTL-24

### Resilience: fail-closed behaviour, HA, backup, DR testing

**Objective.** Keep the platform available without ever trading availability for weaker controls, and recover quickly from loss.

**Enforcement:** deterministic · **Type:** P, V · **Component:** Platform · **Phase:** P1/P5 · **Owner (role):** Platform operations · **Status:** specified

**How it works**

1. Fail-closed rules apply for PDP, registry, policy bundle, revocation lookup and audit capacity.
2. Gateways run at least 3 replicas across zones; Postgres has a synchronous replica; OPA runs next to each gateway.
3. Backups with point-in-time recovery and restore tests, including audit chain verification after restore.
4. Disaster-recovery exercises are timed and fail if the restored audit chain does not verify.

**Prevent**

- Single failures do not open access.

**Detect**

- Health, replication lag, bundle age, probe failures.

**Respond**

- Runbook failover and restore procedures.

**Recover**

- Region failover and failback.

**Parameters**

- Availability: 99.95 percent monthly (Phase 5).
- RPO at most 5 min; RTO at most 30 min (Phase 5).
- Gateway replicas: at least 3.

**Failure behaviour.** By design: deny when dependencies fail; the cost is business agents stop.

**False positives**

- Fail-closed denies valid calls during outages.

**False negatives**

- Untested recovery paths.

**Bypass scenarios**

- Operators loosening fail-closed to restore service (prohibited by the runbook).

**Residual risk.** Availability impact on business agents; targets are unmeasured proposals.

**Requirements:** FR-AUTHZ-8, FR-AUD-7, NFR-3..4

**Threats:** E, X8

**Tests:** TC-Z5, TC-Z6

**Depends on controls:** CTL-13

**Evidence required**

- HA design and configuration.
- Backup, restore and DR exercise reports.

**Metrics (KPI/KRI)**

- Availability and error budget.
- Restore test success.
- Time to restore in exercises.

## CTL-25

### Compliance evidence generation and framework mapping governance

**Objective.** Produce evidence for controls and keep framework mappings reviewed and honest about what they claim.

**Enforcement:** hybrid · **Type:** D · **Component:** Compliance engine · **Phase:** P3 · **Owner (role):** Compliance liaison · **Status:** specified

**How it works**

1. Controls and mappings are versioned in source control; each mapping is labelled mandatory, guidance or voluntary.
2. Evidence packs are generated per control and period from audit and registry data, signed and hash-listed.
3. Legal and compliance review mappings before release and on framework changes; the review date is recorded.
4. The system states that it supports evidence collection and does not assert compliance.

**Prevent**

- Unreviewed mappings are not released as authoritative.

**Detect**

- Controls without evidence; mappings past review date.

**Respond**

- Open remediation items against controls.

**Recover**

- Regenerate packs after corrections.

**Parameters**

- Mapping review interval: to be set.

**Failure behaviour.** Evidence generation failure does not affect enforcement; it raises an alert.

**False positives**

- Mappings that overstate coverage.

**False negatives**

- Applicable frameworks missing from the matrix.

**Bypass scenarios**

- Treating a mapping as proof of compliance.

**Residual risk.** Mappings are unverified until reviewed; jurisdictions were not specified.

**Requirements:** FR-COMP-1..5

**Threats:** X6

**Tests:** TC-Z6

**Depends on controls:** CTL-13

**Evidence required**

- Signed evidence packs.
- Mapping review records.

**Metrics (KPI/KRI)**

- Controls with current evidence.
- Mappings past review date.

**Unverified claims.** All framework identifiers in the matrix are unverified.

## CTL-26

### Discovery and coverage reporting (known gaps)

**Objective.** Find agents and servers outside the gateway and report coverage gaps honestly.

**Enforcement:** advisory · **Type:** D · **Component:** Discovery · **Phase:** P2/P3 · **Owner (role):** Security engineering · **Status:** specified

**How it works**

1. Collectors read the Kubernetes API, MCP client configuration files, egress logs and cloud inventories.
2. Findings enter the registry as unregistered assets for triage.
3. The dashboard lists coverage gaps such as unmanaged endpoints and direct connectors.

**Prevent**

- None directly; network policy (CTL-08) blocks direct paths.

**Detect**

- Unregistered servers and agents; direct connections.

**Respond**

- Owners register or retire the asset; security blocks it.

**Recover**

- None directly.

**Parameters**

- Collection interval: to be set.

**Failure behaviour.** Collector failure is reported as a coverage gap, never as zero findings.

**False positives**

- Test or experimental servers listed.

**False negatives**

- Endpoints on personal devices and servers on networks the collectors cannot see.

**Bypass scenarios**

- Intentional hiding of local stdio servers.

**Residual risk.** Unmanaged endpoints stay uncontrolled (threat X2); this control only reports them.

**Requirements:** FR-INV-5..7

**Threats:** X2, C

**Tests:** TC-X2

**Depends on controls:** CTL-01

**Evidence required**

- Discovery results and coverage-gap reports.

**Metrics (KPI/KRI)**

- Unregistered assets by age.
- Coverage gaps open.

## CTL-27

### Secure development and change management for the platform

**Objective.** Stop the platform itself from becoming the weakest point.

**Enforcement:** hybrid · **Type:** P · **Component:** CI/CD, process · **Phase:** P1 onward · **Owner (role):** Engineering management / platform security · **Status:** specified

**How it works**

1. CI runs static analysis, secret scanning, dependency and image scanning, SBOM generation and signing; failures block release.
2. Changes are classified as standard, security-relevant or emergency with matching approvals; security-relevant changes roll out via shadow mode and canary.
3. Data plane and control plane use separate deployments and credentials; the gateway holds no long-lived upstream secrets.
4. A dedicated penetration test covers the gateway and control plane.

**Prevent**

- Vulnerable or unsigned artifacts and unreviewed changes reach production.

**Detect**

- Gate failures; runtime anomalies on platform pods.

**Respond**

- Rollback; isolate and redeploy from signed images.

**Recover**

- Rebuild from clean sources; rotate reachable secrets.

**Parameters**

- Patch deadlines for critical vulnerabilities: to be set.

**Failure behaviour.** Any failed gate blocks the release.

**False positives**

- Gate failures on unreachable vulnerable code.

**False negatives**

- Unknown vulnerabilities; logic flaws not found by tools.

**Bypass scenarios**

- Emergency changes that skip review (reviewed afterwards).

**Residual risk.** Compromise of the gateway or control plane remains possible (threat X8); impact is limited by short-lived credentials and plane separation.

**Requirements:** NFR-9

**Threats:** X8, L

**Tests:** TC-L3, TC-X8

**Evidence required**

- CI gate results and SBOMs.
- Change approvals and penetration test reports.

**Metrics (KPI/KRI)**

- Emergency changes per quarter.
- Time to patch critical vulnerabilities.

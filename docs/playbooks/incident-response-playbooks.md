# Incident Response Playbooks: AgenticSecCtl

| | |
|---|---|
| Version | 0.2 (design-stage draft) |
| Status | Written before any implementation exists. Procedures are manual and describe intended use of platform capabilities (quarantine, revoke, kill switch, evidence snapshot; FR-IR-*, FR-AUTO-4/5). Automation with approval gates is Phase 4 (FR-IR-4). Names of commands, queries and dashboards are placeholders `[TBD]` until built. |
| Depends on | `Plan/functional-spec.md` v0.6, `Plan/architecture.md` v0.5 (audit event vocabulary, Section 4.8), `Plan/threat-model.md` v0.5, `docs/testing/cases.md` v0.5, `docs/runbooks/operational-runbook.md` v0.3 |
| Audience | Incident commanders, security on-call, platform on-call, compliance and legal liaisons, agent and server owners |
| Scope | Security incidents affecting AI agents, MCP servers, tools and the platform itself. Availability and routine operations are in the operational runbook. |
| Not legal advice | Notification duties (regulators, customers, card brands, supervisory authorities) are decided by legal and compliance. Deadlines and thresholds in any regulation must be checked by them; none are asserted here **[VERIFY with legal]**. |

## 1. How to use this document

1. Classify the event with Section 3 and open an incident.
2. Run the **common phases** (Section 4) in order: Triage → Contain → Preserve → Investigate → Eradicate → Recover → Review.
3. Use the scenario playbook (Section 6) for scenario-specific signals, containment choices, investigation questions and recovery conditions. Several incidents combine playbooks (for example, PB-03 can become PB-04).
4. Record every action in the incident timeline with time, person, and evidence reference.

Principles: contain first, investigate second; preserve evidence before changing state; never bulk-approve to restore service; never weaken a control to end an incident; every override or break-glass use is audited.

## 2. Roles

| Role | Responsibility |
|---|---|
| Incident commander (IC) | Owns the incident, assigns roles, decides containment scope, runs the timeline and communications cadence |
| Security on-call | Triage, containment actions, investigation, policy/rule changes |
| Platform on-call | Infrastructure actions, restores, isolation of pods/nodes |
| Agent owner / server owner | Business context, remediation of their asset, reapproval request |
| Compliance liaison | Evidence handling, regulatory and contractual notification decisions with legal |
| Legal / privacy | Notification obligations, privilege, customer communications |
| Communications lead | Internal and external messages (only when IC requests) |
| Scribe | Maintains the incident timeline |

Separation of duties still applies during incidents: the person who suspends an agent does not resume it (FR-AUTO-5, unless the emergency policy states otherwise); override of Critical findings needs two approvers (SoD-2); break-glass follows FR-ADM-6; operators do not read raw evidence.

## 3. Severity and classification (single incident severity model)

One scale, SEV1 to SEV4, is used for every incident, whether it started as an operational problem or a security event (this section is the canonical definition; the operational runbook Section 3 refers to it). Each incident is rated on two dimensions and its severity is the **higher** of the two. The incident record stores both ratings and the reason, so ratings can be audited.

| Severity | Operational impact | Security impact | Examples | Initial response |
|---|---|---|---|---|
| SEV1 | Platform-wide outage (fail-closed denial for all or most tenants), loss of audit capability, data-plane or control-plane unavailable beyond the recovery target | Confirmed or strongly suspected compromise of the platform; confirmed exfiltration of regulated or confidential data; audit integrity failure; execution of an unapproved high-impact action with material impact | PB-11, PB-12, confirmed PB-04, total PDP or registry loss | Page incident commander, security and platform on-call immediately; acknowledge in 5 minutes |
| SEV2 | One tenant or region down; PDP or registry degraded; sustained latency breach; quarantine storm | Confirmed malicious tool or server; credential compromise of an agent; credible blocked exfiltration; supply-chain compromise found before production use | PB-01, PB-02, PB-05, PB-09, runbook 8.9 | Acknowledge in 15 minutes; page the relevant on-call |
| SEV3 | Single component degraded with no customer impact; backlog growth | Suspicious activity with controls holding; single-agent runaway; rule-triggered findings under review | PB-06 (blocked), PB-07 | Acknowledge in 4 hours; ticket |
| SEV4 | Cosmetic or informational | Informational or false positive | No action beyond record | Next business day |

Targets are proposals `[TBD]` (parameter register PAR-O-23). Rules: when unsure, classify one level higher and reduce after triage; reclassify as facts emerge and record why; an operational incident that becomes a security incident (for example a quarantine storm that proves to be an attack) takes the higher rating and switches to the matching playbook without opening a second incident; if the two dimensions give different ratings, the incident commander owns the rating and records the reasoning.

**Common triage questions** (answer in the first 15 minutes): What asset (agent, server, tool, tenant, platform component)? Which data classes could be involved? Is the activity ongoing? Did any call succeed or was it denied (check `authz.allow` vs `authz.deny`)? Is any human or customer data affected? Is this a test (red team, game day)?

## 4. Common phases (apply to every playbook)

### 4.1 Triage
- Open the incident (`incident.opened`) with severity, owner and affected assets.
- Pull the relevant audit events by agent, server, tool, session and time window; check chain verification state (`audit.verify.failed` means go to PB-12 first).
- Decide containment scope using the table in 4.2.

### 4.2 Contain
Choose the narrowest action that stops the harm; widen if uncertain.

| Action | Effect | Use when | Reference |
|---|---|---|---|
| Quarantine tool | Removed from lists; calls denied | Tool definition or behaviour suspect | FR-DRIFT-3, FR-IR-2 |
| Quarantine server | All its tools blocked | Server compromised or hostile | FR-IR-2 |
| Quarantine agent / kill switch | Agent calls denied within 5 s | Agent compromised, runaway, or abusing | FR-AUTO-4, FR-IR-2 |
| Tenant suspend | All tenant agents denied | Cross-tenant or tenant-wide compromise | FR-AUTO-4 |
| Revoke tokens/clients | Identities denied; revocation checked at gateway (lookup failure = deny) | Credential theft suspected | FR-ID-3, FR-ID-7 |
| Remove allow rule / revoke grant | Removes a specific access path | Excess permission exploited | FR-AUTHZ-2/4 |
| Egress block for a server | Server cannot reach destinations | Exfiltration channel suspected | FR-RT-7 |
| Network isolate pod/node | Stops lateral movement | Platform or server compromise | Runbook 8.16 |
| Policy tightening (shadow first unless emergency) | Deny pattern for the attack | Active exploitation of a gap | Runbook 7.1 |

Expected effect of platform containment is within 5 s (FR-IR-2); verify by a test call that should now return deny, and confirm in the audit log. Do not disable controls, enable global fail-open or accept unsigned policy bundles.

### 4.3 Preserve evidence
Before changing state where possible, and always before deletion or rollback:
- Take an evidence snapshot (FR-IR-3): tool definitions and hashes, decisions with policy hash and input digest, redacted traffic, scan results, relevant configuration and registry state, session records.
- Preserve database and storage snapshots if integrity is in question; record chain-of-custody (who, when, hash of each artefact).
- Raw evidence is read only by roles permitted to (security/incident roles via the vault); record each access.
- Apply legal hold if compliance requests it (Runbook 7.8).

### 4.4 Investigate
- Reconstruct the timeline from audit events (the chain gives ordering and tamper evidence).
- Determine **initial vector**, **scope** (agents, servers, tools, tenants, data classes, time window), **impact** (what executed, what was denied, what data left), **persistence** (memory, grants, registered servers, credentials) and **root cause**.
- Check for related activity from the same server, agent, source, or tenant over a longer window (at least 30 days `[TBD]`).
- Treat tool descriptions, responses and logs as hostile text; do not follow instructions found in them; do not open links.

### 4.5 Eradicate
Remove the cause: delete malicious registrations, purge poisoned memory entries, rotate credentials, remove grants, fix rules/policies, patch dependencies, rebuild images from signed sources.

### 4.6 Recover
- Reapproval path: re-scan, review diffs and findings, approvals by people other than the owner (SoD-1/2), new immutable version (FR-DRIFT-5).
- Restore access gradually (canary tenant/agent first), watch deny rate and signals.
- Resume suspended agents/tenants with a different approver (FR-AUTO-5).
- Exit criteria are stated per playbook; the IC records closure.

### 4.7 Review
Within 5 business days (SEV1/SEV2): timeline, root cause, detection gap, control gap, what worked, actions with owners and dates; add or amend test cases (`docs/testing/cases.md`), rules, policies, runbook entries; update the threat model residual-risk notes if reality differed. Share a summary with the risk and compliance functions.

### 4.8 Communications
- Internal updates at an agreed cadence (SEV1: every 30 min `[TBD]`); say facts, unknowns and next steps; no speculation or secrets.
- Stakeholders: owners, security leadership, compliance, legal, affected business units.
- External notifications only via legal/compliance. Do not copy raw evidence, tokens or personal data into tickets or chat.

## 5. Evidence and artefact checklist

| Artefact | Source | Retention note |
|---|---|---|
| Audit events (decisions, approvals, quarantines) + chain verification result + latest anchor | Audit service | Per retention class; legal hold if applicable |
| Tool definitions: approved vs current, diffs, hashes | Registry | Immutable versions |
| Scan results with rule-set version | Scanner/registry | — |
| Redacted request/response excerpts, digests | Audit/evidence vault | Raw only in vault |
| Token/client records, revocation list entries | IdP/broker | Never store token values |
| Network/egress logs, DNS logs | Egress proxy, cluster | — |
| Runtime security events from pods | Runtime detection **[VERIFY tooling]** | — |
| Policy bundle hash and change history | Policy store | — |
| Incident timeline, decisions, approvals | Incident record | Permanent record |

## 6. Scenario playbooks

Each playbook lists: **Trigger / detection**, **Initial severity**, **Contain**, **Investigate**, **Eradicate and recover**, **Exit criteria**, **Related tests and requirements**. Common phases (Section 4) apply throughout.

---

### PB-01 Malicious or poisoned tool found (tool poisoning)
- **Trigger / detection:** Critical or High scan finding on a registered or approved tool (hidden instructions, override text, credential requests, exfiltration URLs); report from a reviewer; external disclosure about a server; FR-SCAN-9 re-scan finds a Critical finding on an approved tool.
- **Initial severity:** SEV3 if never approved or never callable; SEV2 if the tool was approved/callable; SEV1 if executed with sensitive-data impact.
- **Contain:** Quarantine the tool and, if the server is untrusted, the server. Remove from agent allow rules. Check `authz.allow` events for calls to the tool since approval.
- **Investigate:** When approved and by whom (SoD verification; was an override used?); which agents invoked it; what arguments/data were passed (DLP matches, `dlp.match`); did other tools or agents follow its instructions; was the definition identical at approval (hash history)? Review other tools from the same server or author.
- **Eradicate and recover:** Reject the tool; if the server is legitimate and compromised, require the owner to remediate; add a regression sample to the scanner corpus and the rule if the finding was missed earlier; re-scan the server's other tools; reapproval via new version.
- **Exit criteria:** Tool rejected or reapproved clean; no remaining callable copies; affected agents reviewed; rule gap closed.
- **Related:** Threat A, X1; TC-A1..A5; FR-SCAN-*, FR-DRIFT-*.

### PB-02 Rug pull / unauthorised definition change
- **Trigger / detection:** `tool.quarantined` with a hash mismatch; drift alert; quarantine storm (see runbook 8.9).
- **Initial severity:** SEV3 for a single benign-looking change; SEV2 if the diff contains instructions, new parameters enabling exfiltration or execution, or the change followed approval of a third-party server; SEV2+ for multiple tools at once.
- **Contain:** Keep quarantine in place; confirm gateways deny the tool (test call). Suspend nothing else unless calls succeeded between change and quarantine (check call-time check, FR-DRIFT-7).
- **Investigate:** Field-level diff; compare with server release notes and owner statement; time of change vs time of first quarantine; any calls in the window; same change across tenants; did the server also change behaviour (response shape/size) with the same definition (FR-DRIFT-6, Phase 4)?
- **Eradicate and recover:** If benign: owner explains, re-scan, approve a new version. If malicious: treat as PB-01 plus PB-09 (supply chain) for the server and its package; consider revoking the server's trust and credentials.
- **Do not:** bulk-approve; extend cache TTL to hide the problem.
- **Exit criteria:** All drifted tools resolved (approved new version or rejected); root cause on the owner side known.
- **Related:** Threat B, X7; TC-B1..B4, TC-Z3.

### PB-03 Indirect prompt injection with attempted or executed action
- **Trigger / detection:** `inject.signal` followed by an unusual tool request; taint-rule denial (`authz.deny` with taint reason); approval request for an action the user did not request; agent owner report.
- **Initial severity:** SEV3 if denied; SEV2 if a write/execute/send action executed from untrusted content; SEV1 if sensitive data left (then also PB-04).
- **Contain:** Suspend the session/agent if actions are ongoing; quarantine the source tool/server that delivered the content if it is the carrier (not necessarily malicious: could be a web page or ticket); block the content source if internal.
- **Investigate:** Source of the untrusted content (system, URL, document ID, author); the injected text; which tool calls followed; whether approvals were granted (and by whom, with what args hash); whether the same content exists in memory/RAG (then PB-08); whether detectors missed or flagged it.
- **Eradicate and recover:** Remove or sanitise the content at source; add detection samples (shadow mode first); tighten taint or approval policy where the action class was not treated as high-impact; resume the agent.
- **Exit criteria:** Content removed; no further calls from it; policy or rule gap addressed; any executed actions reversed or accepted by owner.
- **Related:** Threat D, K; TC-D1..D5, TC-K3; FR-RT-4/5/9, FR-AUTHZ-5.

### PB-04 Data exfiltration or leakage (including cross-tenant)
- **Trigger / detection:** `dlp.match` with block failures or high volume; `egress.blocked` spikes; cross-tenant access alert; customer or partner report; unusual outbound volume.
- **Initial severity:** SEV3 if blocked; SEV2 if data left but low sensitivity; SEV1 if regulated or confidential data left, or cross-tenant exposure confirmed.
- **Contain:** Kill switch the agent(s) involved; block egress for the server; revoke relevant tokens; for cross-tenant suspend the affected tenants' access to the implicated component. Preserve evidence first for confirmed leaks.
- **Investigate:** What data classes, how many records/subjects, which tenant; exfiltration channel (tool parameter, markdown link, server callback, DNS); who/what initiated (injection, malicious tool, compromised agent, insider); whether data reached an external party; whether redaction worked; scope time window.
- **Eradicate and recover:** Close the channel (egress allowlist, rule, policy); rotate exposed credentials; remove poisoned instructions; fix tenant isolation bug if cross-tenant (also add test); restore access gradually.
- **Notifications:** The compliance liaison and legal assess privacy, contractual, sector and regulator notification duties as soon as personal or regulated data may be involved, in parallel with containment **[VERIFY obligations with legal]**.
- **Exit criteria:** Channel closed; affected parties and regulators handled as legal decides; data owners informed; lessons applied.
- **Related:** Threat I; TC-I1..I4, TC-D3, TC-D5; FR-RT-6..9.

### PB-05 Credential, token or session compromise; agent impersonation
- **Trigger / detection:** `authn.fail` patterns (replay from new client, wrong audience, session–client mismatch); use of a token from unexpected network; new client registrations; secrets found in logs or repositories (TC-G5 failure); IdP alert.
- **Initial severity:** SEV2; SEV1 if privileged or platform credentials, or evidence of use for data access.
- **Contain:** Revoke tokens and clients at IdP and broker; confirm gateway denies (FR-ID-3, FR-ID-7); suspend the agent; rotate upstream credentials the broker minted for the affected server; invalidate sessions.
- **Investigate:** How the credential leaked (logs, repo, endpoint, malware, insider); window of misuse; calls made (allow events); whether sender binding was active (TC-G1 mode) or only short TTL; related identities.
- **Eradicate and recover:** Issue new credentials with owner approval; fix the leak source (redaction bug, secret in config); search for the same secret elsewhere; shorten token lifetimes if justified; confirm no secrets in logs (TC-G5).
- **Exit criteria:** Old credentials dead; new credentials issued under SoD; leak source closed; monitoring shows no further misuse.
- **Related:** Threats F, G; TC-F1..F2, TC-G1..G5; FR-AUTHN-*, FR-ID-*.

### PB-06 SSRF or internal network probing
- **Trigger / detection:** `ssrf.blocked` bursts; registration attempts to metadata/internal addresses; `egress.blocked` from server pods; access attempts to cloud metadata endpoints; internal service logs showing requests from the platform.
- **Initial severity:** SEV3 when blocked at the guard; SEV2 if a server pod or the scanner reached an internal service; SEV1 if cloud credentials or internal data were obtained.
- **Contain:** Quarantine the registering server and owner's registrations; block the source; for any successful request isolate the pod, revoke cloud role sessions reachable from the pod/node, and rotate metadata-derived credentials **[VERIFY per cloud]**.
- **Investigate:** Targets attempted; which attempts succeeded (internal service and metadata logs); whether guard or network policy failed, or whether the traffic came from server-side code outside the guard; owner intent; whether the guard's allowlist exceptions were involved.
- **Eradicate and recover:** Fix guard/allowlist gap; remove exceptions; enforce metadata hardening (IMDSv2, pod-level metadata block) **[VERIFY per cloud]**; add the payload to the SSRF corpus; reapprove server only after remediation.
- **Exit criteria:** No successful internal access, or all exposed credentials rotated; gap fixed and tested.
- **Related:** Threat H; TC-H1..H4, TC-I4; FR-SSRF-*, FR-RT-7.

### PB-07 Agent autonomy abuse: runaway loop, budget exhaustion, unauthorised transaction
- **Trigger / detection:** `limit.exceeded`, `session.suspended`; budget/cost alerts; repeated delegation denials; approval flood; unexpected payments or irreversible actions.
- **Initial severity:** SEV3 for contained loop; SEV2 if costs or irreversible actions occurred; SEV1 for material financial loss or regulated transaction.
- **Contain:** Kill switch on the agent (and tenant if widespread); cancel pending approvals; reverse or block queued actions with the owning system.
- **Investigate:** Trigger (bug, injection, malicious prompt, misconfigured limits); the call sequence; whether approvals were needed and obtained; limits in effect; blast radius per tenant.
- **Eradicate and recover:** Correct limits (change process), fix agent logic, add loop pattern to detection; resume by a different approver (FR-AUTO-5); reconcile transactions with the business owner.
- **Exit criteria:** Agent stable under limits; affected transactions reconciled; control gap closed.
- **Related:** Threat K; TC-K1..K3, TC-M1; FR-AUTO-*.

### PB-08 Memory or RAG poisoning
- **Trigger / detection:** Instruction-like content flagged on retrieval; unexplained behaviour change after memory writes; retrieval returning content with `untrusted` provenance acting as instructions; vector-store integrity alert.
- **Initial severity:** SEV3; SEV2 if poisoned content influenced actions; SEV1 if it caused exfiltration or high-impact actions.
- **Contain:** Suspend affected agents or restrict them to read-only; disable ingestion from the suspect source; take a snapshot of the memory/vector store.
- **Investigate:** Identify entries by source, session, time, agent; trace their writers; determine which agents retrieved them and what they did; check cross-agent contamination via shared stores.
- **Eradicate and recover:** Roll back/purge entries by source or window (FR-MEM-4); rebuild embeddings if needed; fix the ingestion control; add retrieval inspection or provenance label; resume gradually.
- **Exit criteria:** No poisoned entries remain; verified by test queries; ingestion fixed.
- **Related:** Threat J; TC-J1..J2; FR-MEM-*. Note: depends on Phase 4 capabilities; before then, procedures rely on owner tooling.

### PB-09 Supply-chain compromise (package, image, dependency, model artefact, plugin)
- **Trigger / detection:** Vulnerability or malware advisory for a deployed component; failed signature/provenance; typosquat finding; unexpected outbound connections from a server pod; CI gate failure for a release candidate.
- **Initial severity:** SEV3 if caught pre-production; SEV2 if deployed to non-production or low-risk servers; SEV1 if deployed in production data paths.
- **Contain:** Quarantine affected servers; stop rollouts; block the image digest at admission; rotate credentials available to the component; isolate pods.
- **Investigate:** Use SBOMs to list every deployment containing the component; check provenance/signature; look for IOCs (connections, files); determine time of introduction and exposure.
- **Eradicate and recover:** Rebuild from known-good, signed sources and pinned digests; remove the component; rescan fleet; require third-party intake review (FR-SUP-3) before reuse; add detection (typosquat rule, admission rule).
- **Exit criteria:** No affected component deployed; credentials rotated; admission and CI prevent recurrence.
- **Related:** Threat L; TC-L1..L3; FR-SCAN-5, FR-SUP-*.

### PB-10 Inter-agent abuse (circular delegation, privilege amplification, cross-agent injection)
- **Trigger / detection:** `delegation.denied` bursts; unusual delegation graph shapes; permissions used by a sub-agent beyond the delegator's; cross-agent messages carrying instructions from untrusted sources.
- **Initial severity:** SEV3; SEV2 if amplification succeeded; SEV1 if high-impact action executed.
- **Contain:** Suspend agents in the chain; remove delegation permission between agents; quarantine the originating tool or content (PB-03).
- **Investigate:** The delegation chain and effective permissions per hop; policy gaps in intersection logic; original source of instructions.
- **Eradicate and recover:** Fix policy; add depth/cycle limits where missing; reapproval of delegation allow rules by non-requesters.
- **Exit criteria:** Delegation rules verified (TC-M1, TC-M2); no effective permission exceeds delegator's.
- **Related:** Threat M; TC-M1..M2; FR-ID-4..6. Phase 4 capability.

### PB-11 Suspected gateway or control-plane compromise (SEV1)
- **Trigger / detection:** Runtime security alerts on gateway/control-plane pods; unexpected processes or connections; credential misuse from platform identities; unexplained policy or registry changes; audit chain anomalies (go also to PB-12); report from penetration test or external party.
- **Initial severity:** SEV1.
- **Contain:** Do not debug in place. Isolate the affected pods/nodes by network policy; restrict the platform's outbound access; freeze deployments; preserve forensic images and logs; rotate platform credentials, policy-bundle signing keys, broker credentials, and IdP client secrets for platform components; consider tenant-level suspension if data exposure is plausible.
- **Investigate:** Initial access vector (image, dependency, exposed endpoint, stolen credential, insider); what the attacker could reach (short-lived credentials only? vault? control plane?; see TC-X8 expectations); whether policy bundles, registry entries, approvals or grants were changed (`policy.changed`, `tool.approved`, `grant.created`); whether audit records were altered; lateral movement; tenant data exposure.
- **Eradicate and recover:** Redeploy from signed images in a clean namespace; rotate all reachable secrets; re-verify registry and policy against source control and approvals; re-verify audit chain against anchors; re-approve tools whose records are doubtful; staged restoration with heightened monitoring; external security review before declaring closure.
- **Notifications:** Compliance and legal assess obligations early **[VERIFY with legal]**.
- **Key compromise:** if signing, anchor, broker or encryption keys are or may be exposed, follow the key compromise procedure for that key class (FR-KEY-5; exercise TC-Z32): revoke, rotate with overlap, re-sign bundles and images, re-verify the audit chain and anchors.
- **Exit criteria:** Clean redeploy verified; attacker access path closed; all reachable credentials rotated; registry/policy/audit verified or rebuilt; independent review completed.
- **Related:** Threat X8; TC-X8, TC-Z6; NFR-9; FR-ADM-6.

### PB-12 Audit integrity failure (SEV1)
- **Trigger / detection:** `audit.verify.failed`; sequence gap; anchor mismatch; unexplained DB role activity on audit tables.
- **Initial severity:** SEV1.
- **Contain:** Freeze changes to audit-related components; restrict DB administrative access; preserve database and storage snapshots and the anchor store state; ensure gateways still buffer events and, if the audit sink is unreliable, high-impact calls are denied (FR-AUD-7).
- **Investigate:** Locate the first bad sequence by running verification on the live DB and on backups; compare to anchors; list who/what had write access; treat as potential insider or compromise (consider PB-11, PB-13); determine whether events were deleted, modified or reordered, and what they covered.
- **Eradicate and recover:** Do not repair the chain. Restore from the last verified backup if appropriate and document the gap, keeping the compromised copy as evidence; re-anchor from a verified head; reconstruct missing facts from other sources (SIEM exports, gateway buffers, IdP logs) and mark them as reconstructed.
- **Exit criteria:** Cause identified; verified chain going forward; gap documented and accepted by compliance; access controls fixed.
- **Related:** Threat X6, X8; TC-Z6; FR-AUD-1..7; Runbook 8.11.

### PB-13 Insider or approver abuse (unauthorised approval, override misuse, policy tampering)
- **Trigger / detection:** Approval or override that contradicts findings; approvals concentrated on one pair of people (collusion pattern); `policy.changed` outside change process; break-glass use without ticket; requester approving own request attempts (`approval.denied`).
- **Initial severity:** SEV2; SEV1 if used to enable data theft or if tied to PB-11/PB-12.
- **Contain:** Suspend the involved accounts' approval rights (security admin, with HR/legal consultation as required); quarantine tools approved by them under suspicion; revert policy bundles to the last reviewed signed version; rotate break-glass credentials.
- **Investigate:** All approvals/overrides by the people in scope, over a defined window; compare policy history to source control and reviews; check whether the approved tools/policies were exploited; interview via HR/legal processes (not the platform team alone).
- **Eradicate and recover:** Re-review affected tools (second reviewers); tighten SoD or add dual control; recertify approvers; review break-glass procedures.
- **Exit criteria:** All questionable approvals re-reviewed; policy verified against source control; access recertified.
- **Related:** Threat X6, E; TC-E4, TC-X6; SoD-1..3; FR-ADM-6.

### PB-14 Tool execution attack or suspected container escape
- **Trigger / detection:** Argument guard events for command/SQL/path patterns; runtime alerts (unexpected shell, privilege escalation, file access outside roots); file upload malware detection; pod behaviour deviating from baseline.
- **Initial severity:** SEV3 if guard blocked; SEV2 if execution succeeded in a sandbox; SEV1 if escape or host/node access is suspected.
- **Contain:** Quarantine the tool/server; isolate the pod and node; revoke credentials mounted in the pod; stop affected uploads; preserve pod image and volumes.
- **Investigate:** The argument(s) that reached the server; whether the tool schema declared the parameter class correctly; what the process accessed; network connections; node-level indicators for escape; other tenants on the node.
- **Eradicate and recover:** Patch the server/tool; tighten schema, argument guards, sandbox profile (gVisor/Kata **[VERIFY availability]**), read-only filesystem, no network; rebuild nodes if escape suspected; reapproval after fix.
- **Exit criteria:** Root cause fixed and covered by TC-O1..O3 variants; nodes verified or rebuilt.
- **Related:** Threat O; TC-O1..O3; FR-RT-2/3, FR-EXEC-*.

### PB-15 Model endpoint abuse (extraction-like queries, denial of service, substitution)
- **Trigger / detection:** Quota exhaustion alerts; high-volume systematic queries from one or many identities; model identifier mismatch against registry; cost spikes.
- **Initial severity:** SEV3; SEV2 for sustained denial of service or confirmed substitution; SEV1 if substitution affected production decisions.
- **Contain:** Rate-limit or suspend abusing identities; block the endpoint route; for substitution, pin to the registered model and suspend affected agents.
- **Investigate:** Identity behind the traffic; pattern (breadth, systematic probing, distributed); who changed the endpoint or configuration; downstream effects of outputs from an unapproved model.
- **Eradicate and recover:** Tighten quotas; rotate credentials; fix configuration control; review outputs produced by an unapproved model with the business owner.
- **Exit criteria:** Quotas and registry pinning effective; affected outputs reviewed.
- **Related:** Threat N; TC-N1..N2; FR-MOD-*, FR-RT-10. Note: model-internal attacks are out of scope of the platform.

## 7. Cross-playbook decision aids

### 7.1 Which containment first?

| Situation | First action |
|---|---|
| Data may be leaving now | Kill switch on the agent, block server egress, then preserve evidence |
| A tool is the carrier but harm is unclear | Quarantine the tool |
| Credentials may be stolen | Revoke tokens, rotate upstream credentials, suspend the agent |
| Platform or audit integrity in doubt | Freeze changes, isolate, preserve snapshots (PB-11/PB-12) |
| Many tools changed at once | Hold quarantines, diff, check platform release before assuming attack (Runbook 8.9) |
| Unsure, harm possible | Suspend the narrowest scope that stops the activity; widen later |

### 7.2 Recovery gates (apply before returning to service)
1. Cause understood or contained with compensating controls approved by security.
2. Credentials rotated where exposure is plausible.
3. Tools/servers re-scanned and re-approved as new versions by non-owners; Critical overrides dual-approved.
4. Policy bundle verified against source control and signed.
5. Audit chain verified; any gap documented.
6. Canary restoration with monitoring and rollback ready.

### 7.3 Tabletop and test linkage

| Playbook | Suggested exercise / test |
|---|---|
| PB-01, PB-02 | TC-A1, TC-B1, TC-B4 followed by quarantine and reapproval drill |
| PB-03, PB-04 | TC-D3, TC-D5, TC-I1 plus notification decision tabletop with legal |
| PB-05 | TC-G1, TC-G5; token theft tabletop |
| PB-06 | TC-H1..H4; metadata exposure tabletop per cloud |
| PB-07 | TC-K1..K3; kill switch and different-approver resume drill |
| PB-11, PB-12 | TC-X8, TC-Z6; full game day with restore and anchor verification |
| PB-13 | TC-E4, TC-X6; access review exercise |

Exercises run in the isolated test environment; results update the playbook and the test catalogue.

## 8. Templates

### 8.1 Incident record (minimum fields)
Incident ID · severity (initial/current) · status · IC · opened/closed times · affected assets and tenants · data classes involved · detection source · summary · timeline (time, actor, action, evidence ref) · containment actions · evidence index · root cause · notifications decided (by whom, when) · actions and owners · related playbooks and TC IDs.

### 8.2 Handover note
Current status; what is known and unknown; actions in flight; pending approvals; risks if nothing changes in the next hour; next update time.

### 8.3 Post-incident review outline
Facts and timeline · detection (what fired, what did not) · response (what worked, delays, confusion) · root cause · control gaps (prevent/detect/respond/recover) · test and rule changes · policy or runbook changes · residual risk accepted (by whom) · action list with owners and dates.

## 9. Limits and open items
- Procedures are untested; validate through exercises before relying on them (Runbook Section 14).
- Platform actions referenced here (one-action quarantine and revoke, evidence snapshot, incident record) are requirements (FR-IR-1..3, Phase 2); until built, equivalents are manual and slower than the 5 s targets.
- Automated playbooks with approval gates (FR-IR-4) are Phase 4.
- Memory/RAG, inter-agent and supply-chain playbooks depend on Phase 3/4 capabilities; interim procedures rely on owner tooling.
- Legal notification timelines, evidence standards for litigation, and HR processes need input from the respective functions.
- Contact lists, rotas, tooling names and dashboards are `[TBD]`.

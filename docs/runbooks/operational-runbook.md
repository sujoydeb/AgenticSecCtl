# Operational Runbook: AgenticSecCtl

| | |
|---|---|
| Version | 0.3 (design-stage draft) |
| Status | **Written before any implementation exists.** Procedures describe intended operations. Commands, endpoints, metric names, alert names and thresholds are placeholders marked `[TBD]` and must be replaced with real ones when the services are built, then validated in a game day (Section 14). |
| Depends on | `Plan/architecture.md` v0.5 (components, failure behaviour, deployment, audit event vocabulary in 4.8), `Plan/functional-spec.md` v0.7 (FR/NFR IDs), `Plan/threat-model.md` v0.5, `docs/testing/cases.md` v0.5 |
| Audience | Platform operators, on-call engineers, security engineers, incident responders |
| Out of scope | Security incident handling steps beyond first containment: see `docs/playbooks/incident-response-playbooks.md`. Application-level agent debugging. |

## 1. Operating principles

1. **The platform fails closed.** When policy, registry or identity is unavailable, agent calls are denied (FR-AUTHZ-8). An outage of the platform is a business outage for agents; do not "fix" it by disabling controls.
2. **No silent weakening.** Any change that loosens enforcement (fail-open allowlist, shadow mode, policy relaxation, override of a finding) needs the approvals in Section 9 and is audited.
3. **Separation of duties holds in operations.** Operators run infrastructure; they cannot read raw evidence, approve tools, or alter audit records (spec Section 2, SoD-3).
4. **Contain first, investigate second** for suspected compromise: quarantine and revoke, preserve evidence, then diagnose.
5. **Every operational action is recorded** (ticket + audit event or change record).
6. **Measure before changing.** Capture the baseline dashboard state before any rollout.

## 2. Service inventory

| Service | Plane | Purpose | Failure effect | Dependencies |
|---|---|---|---|---|
| Gateway | Data | Enforces the pipeline for every agent call | Agent tool calls fail (deny) | PDP, registry cache, broker, audit outbox, IdP keys (JWKS) |
| OPA (PDP) | Data | Policy decisions | Calls denied (fail-closed) | Policy bundle store |
| Egress proxy / SSRF guard | Data | Only route from servers/scanner to outside | Server egress blocked; imports fail | DNS, allowlists |
| Management API | Control | Registry, approvals, incidents, grants | No new registrations/approvals; existing approved tools keep working from gateway cache until TTL | Postgres, IdP |
| Scanner workers | Control | Imports and scans | Scans queue; no effect on live calls | Egress guard, queue |
| Audit service | Control | Hash chain, evidence, SIEM export, anchoring | Gateway buffers events; high-impact calls denied if buffer full | Postgres, evidence vault, anchor store |
| Dashboard | Control | Human interface | Humans lose UI; API unaffected | Management API, IdP |
| Postgres | Data store | System of record, audit | Control plane down; gateway uses cache until TTL, then denies | Storage, replication |
| Secrets/token broker | Secrets | Short-lived upstream credentials | Upstream calls fail | Secrets manager/KMS |
| Redis (Phase 2) | Data store | Sessions, revocation list | Session loss; revocation checks degrade (see 8.6) | — |
| Kafka (Phase 2) | Eventing | Event streaming to SIEM | Export lag; outbox keeps events | — |
| Evidence vault, anchor store | Secrets | Raw evidence, chain anchors | Evidence capture/anchoring delayed | Object storage |

## 3. Roles, on-call and escalation

| Role | Responsibilities | Cannot |
|---|---|---|
| Platform on-call (L1/L2) | Availability, capacity, deployments, restore | Approve tools; read raw evidence; edit audit |
| Security on-call | Quarantines, policy and rule updates, findings, approvals triage | Change infrastructure access |
| Incident commander | Runs incidents (see playbooks) | — |
| Service owners (per component) | Escalation point for code defects | — |
| Compliance/audit liaison | Evidence requests, retention, legal hold | Alter data |

Escalation (to be filled with names/rotations when staffed `[TBD]`):

Incident severity uses the single SEV1 to SEV4 model defined in `docs/playbooks/incident-response-playbooks.md` Section 3, with an operational and a security dimension; the higher dimension sets the severity. The table below shows the operational dimension and who is paged; it must not define different levels.

| Severity | Operational criteria (see playbooks for the security dimension) | Response target | Page |
|---|---|---|---|
| SEV1 | Platform-wide fail-closed outage, loss of audit capability | Acknowledge 5 min | Platform + Security on-call + incident commander |
| SEV2 | Single tenant or region down, PDP or registry degraded, sustained latency breach, quarantine storm | 15 min | Platform on-call (security on-call if a security cause is possible) |
| SEV3 | Single component degraded with no customer impact, backlog growth | 4 h | Ticket |
| SEV4 | Cosmetic, informational | Next business day | Ticket |

Response targets are proposals `[TBD]`.

## 4. Service levels and key signals

Targets from spec NFR-1..4; they are proposals not yet measured.

| Signal | Target | Source `[TBD metric names]` | Alert |
|---|---|---|---|
| Gateway added latency (deterministic path) | p95 ≤ 25 ms, p99 ≤ 60 ms | Gateway spans | Warn at p95 > 25 ms for 10 min; page at > 50 ms for 5 min |
| Gateway availability | 99.95% monthly (Phase 5) | Probes | Page on burn-rate |
| Deny rate by reason (authn, authz, hash, ssrf, limit) | Baseline per tenant | Audit events | Warn on 3× baseline for 15 min |
| PDP decision latency / errors | p95 within budget; 0 errors | OPA metrics | Page on any sustained errors |
| Policy bundle age | < TTL | OPA bundle status | Page when stale beyond TTL |
| Registry cache age | < 60 s TTL | Gateway | Warn at 80% of TTL |
| Quarantine events per hour | Low single digits | Audit | Page on spike (see 8.9) |
| Audit outbox depth / oldest event age | Near 0 / < 30 s | Gateway, audit service | Warn > 60 s; page when full |
| Audit chain verification | Pass | Verifier job | Page on failure (SEV1) |
| Anchor freshness | Within schedule | Anchor job | Warn when one cycle missed |
| Postgres replication lag, disk, connections | Within thresholds | DB metrics | Standard DB alerts |
| Egress blocked events | Baseline | Egress proxy | Warn on spike (possible attack or misconfig) |
| IdP/JWKS fetch failures | 0 | Gateway | Page on sustained failures |
| Scan queue age | < 15 min | Scanner | Warn |
| Approval queue age | Within business SLA `[TBD]` | API | Notify owners |
| Certificate/token key expiry | > 14 days remaining | Certificate inventory | Warn at 30 days, page at 7 days |

Dashboards to build: gateway health and latency; decisions and denies; audit and anchoring; control plane and database; security posture (findings, drift, quarantines); per-tenant view.

## 5. Routine operations

### 5.1 Daily
- Review overnight alerts, deny-rate shifts and quarantine events.
- Check audit chain verification and anchor jobs succeeded.
- Review approval and scan queues; escalate stale items.
- Confirm backups completed.

### 5.2 Weekly
- Review false-positive and override reports with security; propose rule tuning (Section 8.10).
- Review fail-open allowlist usage (should be near zero) and fail-open flagged decisions.
- Check certificate and key expiry horizon, dependency and image vulnerability reports.
- Review capacity trends.

### 5.3 Monthly
- Restore test of Postgres backup into an isolated environment; verify audit chain on the restored copy.
- Review unused permissions and long-lived JIT/static grants with owners (FR-AUTHZ-6).
- Review role bindings and administrator list.
- Review MCP specification and dependency release notes for compatibility impact (Section 9.9).
- Review retention jobs and legal holds.

### 5.4 Quarterly
- Disaster-recovery exercise (Section 11) and game day (Section 14).
- Recertify approvers and owners; rotate non-automated credentials.
- Re-run penetration or red-team regression subset (`docs/testing/cases.md`).
- Review SLO performance and error budget; update capacity plan.

## 6. Deployment and change management

**Change classes**

| Class | Examples | Approval | Rollout |
|---|---|---|---|
| Standard | Image patch, scaling, rule-set update with tests | Peer review | Staged |
| Security-relevant | Policy bundle change, fail-open allowlist, role changes, override of findings | Peer + security approver; second approver for loosening | Shadow mode first (FR-POL-4) |
| Emergency | Active exploitation fix, containment | On-call + security lead, retrospective review within 2 business days | Immediate with audit |

**Pre-deployment checklist**
1. CI green incl. security gates (secret scan, SBOM, vulnerability scan, signature) and relevant `TC-*` cases.
2. Images signed and pinned by digest; admission policy will accept them.
3. Database migrations are backward compatible with the running version (expand/contract).
4. Rollback plan identified and tested.
5. Baseline dashboard state captured; change window agreed.

**Rollout order** (data-plane safe path): control-plane migrations → API/scanner/audit → OPA bundle (shadow, then enforce) → gateway canary (1 pod, then 25%, 100%) → dashboard. Hold between steps to watch deny rate, latency and error metrics for at least `[TBD]` minutes.

**Rollback triggers:** p95 latency above warn threshold, deny-rate jump unexplained by the change, any audit/verification error, error rate increase, quarantine storm. Rollback procedure: redeploy previous digest; revert policy bundle to previous signed version; do not roll back migrations unless the migration guide says so.

## 7. Standard procedures

### 7.1 Roll out a policy bundle
1. Merge reviewed change; CI runs `opa test`; bundle is built and signed.
2. Publish bundle in **shadow** mode: decisions logged beside current policy, not enforced.
3. Compare: new denies, new allows, per tenant. Investigate every new allow. Security approves.
4. Switch to enforce for one tenant/canary pods, then widen.
5. Verify `policy.changed` event with bundle hash and approver; keep previous bundle for rollback.
6. If gateways report stale/unsigned bundle: they deny; see 8.1.

### 7.2 Update scanner rule set
1. Run the rule-set against the labelled corpus; compare precision/recall to the budget (spec Section 10).
2. Publish new rule-set version; scans record the version (FR-SCAN-2).
3. Re-scan existing approved tools in a low-priority queue; findings on already-approved tools create review items, not automatic quarantine, unless severity is Critical (then quarantine and notify owner) (FR-SCAN-9).

### 7.3 Tool approval backlog handling
1. Prioritise by tool criticality and requester impact.
2. Reviewers follow the approval checklist: findings read, diff reviewed, action class mapping confirmed, egress destinations confirmed, owner confirmed.
3. Critical-finding overrides need two distinct approvers and justification with expiry (SoD-2). Operators never approve.

### 7.4 Tenant onboarding and offboarding
Onboarding: create tenant and keys; configure IdP connection and role bindings; load baseline policy bundle; set retention class and region; configure notification channels; seed agents/servers via discovery; run smoke test (TC-F1, TC-E1, TC-Z5 subset) before enabling traffic.
Offboarding: disable agent access, revoke tokens, export evidence as requested, apply retention/legal hold rules, schedule key deletion after retention (cryptographic erase), record in audit.

### 7.5 Certificate, key and secret rotation
The key inventory, storage, rotation and compromise rules are requirements FR-KEY-1..5; the inventory is reviewed quarterly and the compromise procedure is exercised at least yearly (TC-Z31, TC-Z32).
- **Gateway/service TLS and server pins:** rotate before the 30-day warning; for pinned server certificates the *server owner* submits the new pin, an approver ≠ owner approves, then operators deploy (TC-C2 semantics).
- **IdP signing keys (JWKS):** confirm gateways refresh JWKS on key ID change; keep overlap period.
- **Policy bundle signing key:** rotate with overlap; gateways must trust old and new during window.
- **Broker/upstream secrets:** rotate in the secrets manager; no secrets in manifests; verify no gateway restart is needed (short-lived mint model).
- **Audit anchor credentials:** least privilege, write-only to the anchor store.
- Record each rotation as a change with verification evidence.

### 7.6 Revoke credentials and quarantine (first response)
1. Quarantine the tool, server or agent from the dashboard/API (FR-IR-2). Expected effect within 5 s.
2. Revoke tokens/clients at the IdP and broker; confirm in gateway that revoked identities are denied (check deny reason `[TBD]`).
3. Preserve evidence snapshot before changing anything else (FR-IR-3).
4. Open an incident and hand over to Security on-call; continue with `docs/playbooks/incident-response-playbooks.md` (PB-01..PB-15).

### 7.7 Kill switch (suspend agent or tenant)
Use for runaway agents or suspected tenant-wide abuse (FR-AUTO-4): suspend the agent or tenant; confirm calls are denied within 5 s; record reason; notify owner. Resume requires approver ≠ the person who suspended (FR-AUTO-5; the emergency policy of FR-AUTO-6 is the only exception), unless emergency policy states otherwise.

### 7.8 Retention, legal hold and evidence requests
1. Retention jobs run on schedule by data class (spec NFR-6); never delete under legal hold.
2. Legal hold: compliance liaison sets hold; verify jobs skip held data; test monthly.
3. Evidence request: compliance/audit role generates an evidence pack for control and period (FR-COMP-4); verify hash list; log the export. Operators do not read raw evidence.

### 7.9 Backup and restore
- Postgres: continuous WAL archiving plus periodic base backups; encryption at rest; retention per class. Evidence vault and anchor store replicated/versioned.
- **Restore procedure (outline):** declare incident; stop writers; restore to point in time in an isolated environment; run audit chain verification and compare tip to the latest external anchor; if the chain tip precedes the anchor, treat as data loss and escalate; promote only after verification; resume with gateways in cache-only mode until registry is healthy.
- Restore tests monthly (Section 5.3).

### 7.10 Scaling
- Gateway: scale on CPU, concurrent sessions and p95 latency; keep ≥ 3 replicas across zones.
- Postgres: scale vertically first; read replicas for dashboards; monitor connection limits (use pooling).
- Scanner workers: scale on queue age; cap resources per worker.
- Always scale PDP alongside the gateway when OPA runs as a sidecar.
- Load test after significant changes against NFR-1/5 `[TBD harness]`.

## 8. Failure scenarios and responses

Format: symptoms → impact → diagnose → act → verify → follow-up. Security-originated failures (compromise) go to the incident playbooks.

### 8.1 PDP (OPA) unavailable or bundle stale
- **Symptoms:** spike of denies with reason policy-unavailable/stale; OPA health failing; bundle age beyond TTL.
- **Impact:** all non-allowlisted calls denied (fail-closed). Expected behaviour (TC-Z5).
- **Diagnose:** OPA pod status, bundle fetch errors, bundle signature validation, bundle store reachability.
- **Act:** restart/replace OPA pods; fix bundle store access; if a bad bundle was published, revert to the previous signed bundle (7.1). Do **not** disable signature checking or enable global fail-open.
- **Verify:** denies return to baseline; bundle age < TTL; decision latency normal.
- **Follow-up:** post-incident review; add shadow-mode check that would have caught the bad bundle.

### 8.2 Registry/Management API unavailable
- **Symptoms:** API 5xx, no new registrations or approvals; gateways log registry refresh failures.
- **Impact:** existing approved tools keep working until cache TTL; after TTL expires, denies. Drift quarantines cannot be applied centrally but gateways still deny hash mismatches locally.
- **Diagnose:** API pods, Postgres connectivity, recent migrations or releases.
- **Act:** roll back release; fail over database; scale API. If TTL expiry is near and recovery is unlikely, escalate to SEV1 (consider extending cache TTL only with security approval and an audit record).
- **Verify:** registry age at gateways drops; approval and registration flows work.

### 8.3 Postgres failure or failover
- **Symptoms:** connection errors, replication lag alarms, API and audit write failures.
- **Impact:** control plane degraded; audit events buffered at gateway outbox.
- **Act:** follow HA failover for the DB platform `[TBD]`; confirm new primary; verify no lost transactions (compare last sequence numbers with audit outbox); run audit chain verification; drain outbox.
- **Follow-up:** if any audit sequence gap exists, open a SEV1 integrity incident.

### 8.4 Audit sink down or outbox growing
- **Symptoms:** outbox depth/age alarms; audit service errors.
- **Impact:** until the buffer fills, calls continue; when full, **high-impact calls are denied** (FR-AUD-7, architecture 4.1).
- **Act:** restore audit service or storage; check disk; scale consumers; do not drop events. Verify chain continuity after drain.
- **Verify:** oldest event age < 30 s; chain verification passes; anchor job catches up.

### 8.5 IdP outage or JWKS failure
- **Symptoms:** `authn.fail` spike with key/issuer fetch errors; dashboards cannot log in.
- **Impact:** gateways validate with cached JWKS until expiry; new logins and token issuance fail; after cache expiry all calls denied.
- **Act:** contact IdP owner; confirm JWKS cache duration is sufficient; do not accept unsigned tokens or extend trust to other issuers. Use break-glass (Section 10) for human admin access if SSO is down.
- **Follow-up:** record IdP dependency in the post-incident review; evaluate multi-region IdP options.

### 8.6 Redis unavailable (Phase 2+)
- **Symptoms:** session lookup errors, revocation-list refresh failures.
- **Impact:** session loss forces re-initialisation; revocation checks may degrade.
- **Act:** fail over or restore Redis; **revocation lookup failure must deny rather than skip** (FR-ID-7; confirm configuration in staging `[TBD]`). Restart gateways only if they cannot reconnect.
- **Verify:** TC-G4 and revocation tests pass in the affected environment.

### 8.7 Gateway latency breach
- **Symptoms:** p95/p99 above target; timeouts at agents.
- **Diagnose:** which stage is slow (spans): OPA call, registry refresh, DLP/inspection, upstream server, egress proxy, GC or CPU saturation.
- **Act:** scale out; reduce inline inspection tier by policy only through the change process (do not disable controls ad hoc); isolate a noisy tenant with rate limits; check hostile traffic (TC-Z4 pattern) and apply per-session limits.
- **Follow-up:** capacity review; add a performance regression test.

### 8.8 Egress proxy or SSRF guard problems
- **Symptoms:** imports fail; legitimate server calls blocked; `egress.blocked`/`ssrf.blocked` spike.
- **Diagnose:** DNS resolution issues, allowlist drift, new server endpoint, or real attack traffic.
- **Act:** if legitimate, owner submits an allowlist change approved by an approver (FR-SSRF-5) with expiry; never add broad CIDRs or disable the guard. If suspicious, treat as security event (7.6).

### 8.9 Quarantine storm
- **Symptoms:** many tools quarantined at once.
- **Likely causes:** server-side deployment changed many definitions (benign), hashing/normalisation change after upgrade (platform bug), or supply-chain compromise.
- **Diagnose:** diff several quarantined tools; check whether all changes share a cause; check platform version change; check the server's release notes.
- **Act:** if platform bug, roll back the release that changed canonicalisation (do not mass-approve); if benign server release, re-scan and re-approve in batches with owners; if suspicious, keep quarantined and escalate to incident.
- **Never** bulk-approve to restore service without review of diffs and findings.

### 8.10 False-positive surge from rules or detectors
- **Symptoms:** many blocks of benign traffic or findings on clean tools after a rule/detector update.
- **Act:** roll back rule-set or put the detector in shadow mode (change class security-relevant, second approver); analyse samples; fix; re-test against corpus; re-enable.
- **Note:** shadow mode reduces protection; track duration and report it.

### 8.11 Audit integrity failure (SEV1)
- **Symptoms:** `audit.verify.failed`, sequence gap, anchor mismatch.
- **Act:** freeze audit-related changes; preserve database and storage snapshots; notify security lead and compliance; run verification on backups to find the first bad sequence; treat as potential insider or compromise; open an incident (playbook). Do not "repair" the chain.

### 8.12 Anchor store unavailable
- **Symptoms:** anchor job failures.
- **Impact:** tamper-evidence window grows; no immediate service impact.
- **Act:** restore connectivity; run the job for the missed range; note the gap in the compliance log; escalate if gap exceeds policy `[TBD]`.

### 8.13 Event streaming / SIEM export lag (Phase 2+)
- **Impact:** detections delayed; outbox keeps events.
- **Act:** scale consumers, check Kafka health, SIEM ingest limits; verify no loss by comparing sequence numbers; ensure control characters are escaped before export (FR-AUD-5).

### 8.14 Scanner worker issues
- **Symptoms:** queue growth, worker OOM/timeouts on hostile imports.
- **Act:** confirm resource limits worked (the hostile case should fail within limits, TC-Z2); restart workers; if a particular server repeatedly kills workers, mark the server `import-blocked` and notify the owner; investigate as possible hostile server.

### 8.15 Runaway agent or abuse of budget
- **Act:** use limits and kill switch (7.7); inspect delegation graph for loops (TC-K1, TC-M1); contact agent owner; adjust limits through change process.

### 8.16 Suspected gateway or control-plane compromise (SEV1)
- **Act:** do not debug in place. Isolate the affected pods/nodes (network policy), preserve forensic images/logs, rotate platform credentials and signing keys, redeploy from signed images in a clean namespace, verify audit chain and anchors, notify security lead and compliance. Follow `docs/playbooks/` for the full procedure (see TC-X8 for what an attacker should and should not be able to obtain).

## 9. Specific operational procedures

### 9.1 Fail-open allowlist changes
Only for read-only, low-risk tools, per tenant (FR-AUTHZ-8). Requires security approver + tenant risk owner, written rationale, expiry date, and a weekly review of usage. Every fail-open decision is flagged in audit.

### 9.2 Break-glass access
- Purpose: human administrative access when SSO or the normal approval path is down.
- Rules (FR-ADM-6): accounts stored in the secrets manager, sealed; each use requires an incident ticket and a second person's approval; session recorded; credentials rotated after use; use generates a high-severity audit event and a post-use review within 1 business day.
- Break-glass **cannot** modify or delete audit records, and does not grant access to raw evidence.

### 9.3 Upgrading dependencies and the platform
Use Section 6. For database major upgrades: rehearse in staging with a production-sized restore; keep rollback snapshot.

### 9.4 MCP specification and SDK upgrades
1. Read the revision's changes; identify new surfaces (new capabilities, auth changes).
2. Update the compatibility matrix; add or adjust cases (`TC-P1..P4`) before enabling the new version in production.
3. Enable the new protocol version in the allowlist for canary tenants first.
4. Re-run the threat model delta review for new capabilities (threat model Section 9).

### 9.5 Adding a new MCP server at scale (bulk onboarding)
Prefer discovery import into `unregistered`, then owners register; run scans in batches; require owners and environment fields; track backlog; do not pre-approve in bulk.

### 9.6 Data residency and region changes
Pin tenant data to region at onboarding; moving regions is a project with legal review, export/import and re-anchoring, not an operational toggle.

### 9.7 Decommissioning a server or agent
Quarantine, revoke credentials, remove allow rules, retain history per retention class, mark `retired`; confirm no active sessions.

## 10. Security hygiene for operators
- MFA and least privilege for every operator account; no shared accounts; privileged access time-boxed and logged.
- Operators have no access to raw evidence or secrets; secrets only via CSI mounts or the secrets manager.
- Treat tool descriptions, responses and logs shown in consoles as hostile text (control characters, links).
- No ad hoc debugging that dumps request/response payloads or tokens to logs; use the redacted tracing facilities (AC-9).
- Clipboard/ticket hygiene: never paste tokens or evidence into tickets or chat.
- Patch cadence: critical vulnerabilities in internet-facing or data-plane components in `[TBD]` days; others on the monthly cycle.

## 11. Disaster recovery

| Item | Target (proposal, spec NFR-4) |
|---|---|
| RPO | ≤ 5 min |
| RTO | ≤ 30 min (Phase 5) |

**Scenarios:** loss of a zone, loss of a region, loss of database primary, corruption (logical) requiring point-in-time restore, loss of the control plane only, loss of the IdP.

**Region failover outline `[TBD in Phase 5]`:** declare DR; confirm replica state and last anchored audit head; promote database in secondary region; deploy/scale data plane there; update routing; verify identity connectivity; smoke test (TC-F1, TC-E1, TC-Z5, TC-Z6); announce; reconcile audit chain across regions; schedule failback.

DR exercises quarterly with timed evidence. A DR exercise that restores service but fails audit chain verification is a failed exercise.

## 12. Capacity and cost management
- Track sessions, calls/s, decision rate, payload sizes, inspection time, storage growth for audit/evidence by tenant.
- Plan headroom of at least `[TBD]`% at peak; re-run load tests per release candidate.
- Storage: audit and evidence retention drive growth; tier cold data per retention policy; confirm legal holds before tiering.
- Rate limits and quotas per tenant/agent protect the platform (FR-RT-10, FR-AUTO-1).

## 13. Reporting and communications
- Operational status page/channel for tenants during SEV1/2: what is impacted, whether the platform is **failing closed** (expected) or degraded, ETA, workaround (none that weaken controls).
- Weekly operations report: SLO performance, incidents, changes, quarantines, overrides, fail-open usage, backlog.
- Monthly security report: findings trend, drift events, unused permissions, red-team results.
- Post-incident reviews within 5 business days for SEV1/SEV2: timeline, root cause, detection gap, control gap, action items with owners; link to new or changed test cases.

## 14. Readiness and validation
Before production use, all of the following must be done and evidenced:
1. Replace every `[TBD]` in this document with real metric names, commands, endpoints and thresholds.
2. Run a game day covering 8.1, 8.2, 8.4, 8.5, 8.9, 8.11 and a DR failover.
3. Confirm alert routing reaches on-call and that alerts fire in staging with injected faults.
4. Verify restore from backup plus audit chain verification.
5. Walk through each procedure with someone who did not write it.
6. Security review of break-glass and operator access models.
Owner and date for each item to be assigned.

## 15. Appendices

### 15.1 Quick reference: expected behaviour under failure

| Failure | Expected behaviour | Reference |
|---|---|---|
| PDP down or stale bundle | Deny non-allowlisted calls | FR-AUTHZ-8, TC-Z5 |
| Registry/DB down | Cache until TTL, then deny | Architecture 4.1 |
| Audit sink down | Buffer; deny high-impact when full | Architecture 4.1 |
| IdP down | Cached JWKS until expiry, then deny | 8.5 |
| Revocation lookup failure | Deny | 8.6 |
| Definition hash mismatch | Quarantine, deny | FR-DRIFT-2/3, TC-B1 |
| SSRF guard hit | Block, audit | FR-SSRF-*, TC-H* |
| Limit exceeded | Deny/suspend | FR-AUTO-*, TC-K* |

### 15.2 Items intentionally not specified yet
Command lines, dashboards' exact queries, alert rule definitions, cloud-specific failover steps, staffing and rotas, SLA wording for tenants. These depend on implementation and customer decisions (ADR-1..7, spec Section 12).

### 15.3 Related documents
`Plan/architecture.md` (components and failure design), `Plan/functional-spec.md` (requirements), `Plan/threat-model.md` (threats), `docs/testing/cases.md` (test cases used for smoke and game days), `docs/prd.md` (scope and phases), `docs/playbooks/incident-response-playbooks.md` (incident response).

# Parameter Register

| | |
|---|---|
| Version | 0.3 (closes gaps D4 and G6 in `docs/reviewgap.md`; v0.2 adds PAR-O-26..28 for IG-17; v0.3 adds PAR-O-29 for IG-5) |
| Depends on | `Plan/functional-spec.md` v0.7, `controls/catalogue.md` v0.5, `docs/ci-cd-pipeline.md` v0.6, `docs/deployment-architecture.md` v0.4, `docs/runbooks/operational-runbook.md` v0.3, `docs/governance.md` v0.4 |
| Purpose | One list of every tunable value: those already fixed (with a machine check that every document still states the same value) and those still open (with an owner and a decision gate). A value that is "to be set" anywhere in the documentation must have a row in Section 2. |
| Status | Proposals only; no owner has accepted any row. Owner roles use the glossary in `docs/governance.md`. |

## 1. Fixed parameters (checked by `scripts/check_docs.py`)

Each row names a regular expression and the files that must match it. If a document changes the value, the check fails until every listed file agrees (or the row is updated deliberately). Patterns are matched case-sensitively against the whole file.

| ID | Parameter | Value | Pattern | Files |
|---|---|---|---|---|
| PAR-F-01 | Containment effect time (quarantine, revoke, kill switch) | within 5 seconds | `within 5 s` | `Plan/functional-spec.md`, `docs/runbooks/operational-runbook.md` |
| PAR-F-02 | Definition and registry cache TTL at the gateway | 60 seconds | `60 s` | `Plan/functional-spec.md`, `docs/runbooks/operational-runbook.md` |
| PAR-F-03 | Access token lifetime | 10 minutes or less | `10 min` | `Plan/functional-spec.md`, `controls/catalogue.yaml` |
| PAR-F-04 | Maximum delegation depth (default) | 3 | `default 3` | `Plan/functional-spec.md` |
| PAR-F-05 | Unused-permission report window (default) | 30 days | `default 30` | `Plan/functional-spec.md` |
| PAR-F-06 | Audit retention placeholder | 13 months hot, 7 years cold | `13 months` | `Plan/functional-spec.md`, `controls/catalogue.yaml` |
| PAR-F-07 | Gateway added latency, deterministic path | p95 at most 25 ms | `25 ms` | `Plan/functional-spec.md`, `docs/deployment-architecture.md` |
| PAR-F-08 | Inline classifier latency | p95 at most 150 ms or asynchronous | `150 ms` | `Plan/functional-spec.md` |
| PAR-F-09 | Recovery targets | RPO 5 minutes, RTO 30 minutes | `RPO` | `Plan/functional-spec.md`, `docs/deployment-architecture.md`, `docs/roadmap.md` |
| PAR-F-10 | Redirect hops when redirects are enabled | at most 3 | `max 3` | `Plan/functional-spec.md` |
| PAR-F-11 | Availability target (Phase 5) | 99.95 percent monthly | `99.95` | `Plan/functional-spec.md`, `docs/roadmap.md` |

## 2. Open parameters ("to be set")

Decision gates: **P0** Phase 0 sign-off; **B1** before Phase 1 starts; **P1**, **P2**, **P3**, **P4** during the named phase; **S3** after policy-latency spike; **LT** after load tests. "Source" names the document or control that carries the "to be set" text.

| ID | Parameter | Source | Proposed owner role | Decide by | Notes |
|---|---|---|---|---|---|
| PAR-O-01 | Importer limits: timeout, response size, JSON depth, item count | CTL-02, FR-SCAN-6 | Security engineer | B1 | Needed for TC-Z2 |
| PAR-O-02 | Policy bundle staleness limit | CTL-16, FR-AUTHZ-8 | Security engineer | B1 | Gateways deny beyond it; tested by TC-Z5 |
| PAR-O-03 | Exception expiry for SSRF allowlist entries | CTL-08, FR-SSRF-5 | Security engineer | B1 | |
| PAR-O-04 | Approval timeout | CTL-07, CTL-28 | Product owner | B1 | Timeout means deny |
| PAR-O-05 | Vulnerability severities that fail a build | CTL-17, `docs/ci-cd-pipeline.md` gates G1.6, G2.3 | Security engineer | B1 | |
| PAR-O-06 | SAST severity threshold | `docs/ci-cd-pipeline.md` gate G1.5 | Security engineer | B1 | |
| PAR-O-07 | Patch deadlines for critical vulnerabilities | CTL-27 | Delivery lead | B1 | |
| PAR-O-08 | Decision cache TTL | CTL-06 | Security engineer | S3 | Keyed on policy hash and input digest |
| PAR-O-09 | Per-session call, time and cost limits; loop threshold | CTL-12 | Security engineer | P2 | Test setting uses 50 calls |
| PAR-O-10 | Audit anchor interval; production gateway audit buffer sizing | CTL-13 | Security engineer | P2 | ADR-7; the Phase 1 buffer values are PAR-O-29 |
| PAR-O-11 | Redaction and block actions per tenant | CTL-10 | Compliance liaison | P2 | Needs detector results (spike S4) |
| PAR-O-12 | Sandbox profile and limits per server class | CTL-11 | Security engineer | P2 | |
| PAR-O-13 | Alert thresholds | CTL-14 | Security on-call | P2 | After baselining |
| PAR-O-14 | Notification rate limit (protocol); notification retry policy (UI); maximum counter staleness | CTL-18, CTL-28 | Security engineer | P2 | |
| PAR-O-15 | Discovery collection interval | CTL-26 | Security engineer | P2 | |
| PAR-O-16 | Credential rotation interval and key-class rotation and overlap periods | CTL-04, CTL-30 | Security engineer | P2 | FR-KEY-3 |
| PAR-O-17 | Penetration test and red-team cadence | `docs/ci-cd-pipeline.md` stage 5 | Delivery lead | P2 | |
| PAR-O-18 | Capacity headroom, sizing, cost model | `docs/deployment-architecture.md` Section 8 | Platform operator | LT | |
| PAR-O-19 | Policy shadow period before enforcement | CTL-16, FR-POL-4 | Security engineer | P3 | |
| PAR-O-20 | Mapping review interval | CTL-25 | Compliance liaison | P3 | |
| PAR-O-21 | Quota values per identity (model endpoints) | CTL-21 | Product owner | P3 | |
| PAR-O-22 | Memory retention and rollback window | CTL-19 | Security engineer | P4 | |
| PAR-O-23 | Incident response targets by severity; escalation rotas | `docs/runbooks/operational-runbook.md` Section 3, `docs/playbooks/incident-response-playbooks.md` Section 3 | Incident commander | P2 | Values in documents are proposals |
| PAR-O-24 | Runbook placeholders: commands, metric names, alert names, thresholds | `docs/runbooks/operational-runbook.md` | Platform operator | P1 and P2 | Replace each TBD when built |
| PAR-O-25 | Reference environment and workload for load tests | `docs/testing/performance-test-plan.md` | Test lead | B1 | Proposal exists in the plan |
| PAR-O-26 | Test coverage thresholds (high on `common` security primitives and policy tables, lower elsewhere) | `Plan/implementation-plan.md` Section 7 | Test lead | P1 | Set once the first packages have measured coverage; a guard against untested code, not evidence of quality |
| PAR-O-27 | Database migration tool (plain SQL migrations or a library) | `Plan/implementation-plan.md` Section 4.3, WP-1.5 | Backend engineer | B1 | Needed before WP-1.5 starts; must support tested rollback for development |
| PAR-O-28 | Database access layer and driver | `Plan/implementation-plan.md` Section 4.3, WP-1.5, WP-1.6 | Backend engineer | B1 | Must allow the tenant to be set per transaction, never per session (IG-9) |
| PAR-O-29 | Phase 1 gateway audit buffer: capacity, share reserved for deny events, flush interval, and the longest time the API may be unreachable before calls are denied | `Plan/implementation-plan.md` Section 4.4, WP-1.9 | Security engineer | P1 | Decide before WP-1.9 starts; the flush interval bounds the events lost on a gateway crash |

## 3. Rules

1. A new "to be set" in any document needs a row in Section 2 in the same change.
2. A value moves from Section 2 to Section 1 when decided; add the pattern and files so the check protects it.
3. Code defaults and configuration schemas must match the register (FR-ADM-1).
4. The check script verifies Section 1 patterns and that every control whose parameters say "to be set" is named in Section 2.

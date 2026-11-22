# Implementation Plan Gap Register

| | |
|---|---|
| Version | 0.3 (review of `Plan/implementation-plan.md` v0.1; IG-1 and IG-2 incorporated in plan v0.2 and the Low gaps IG-10, IG-12, IG-13, IG-16, IG-17 in plan v0.3, all pending review) |
| Date | 2026-11-22 |
| Depends on | `Plan/implementation-plan.md` v0.3, `Plan/functional-spec.md` v0.7, `Plan/architecture.md` v0.5, `docs/roadmap.md` v0.4, `docs/data-model.md` v0.1, `docs/authn-authz-design.md` v0.1, `docs/cross-cutting-design.md` v0.1, `docs/testing/cases.md` v0.5, `docs/parameter-register.md` v0.2 |
| Scope | Gaps, errors and inconsistencies found when reading the implementation plan against the specification, architecture, test catalogue, roadmap and the checker script. This register is separate from `docs/reviewgap.md`, which covers the design documents. |
| Method | Scripted re-computation of the Phase 1 requirement and test-case sets with a parser that finds the phase by pattern (not by column position), comparison of the plan's schedule and dependency text with itself, and reading of each work package against the design documents. Nothing was built or executed. |
| Status | Findings. IG-1 and IG-2 are incorporated in plan v0.2 and the checker, and the five Low gaps in plan v0.3 (Section 6); the other 10 are open. Closure wording as in `docs/reviewgap.md` Section 9: "closed, pending review" means changed but not yet reviewed by someone other than the author. Severity: **High** (the plan is wrong or cannot be executed as written), **Medium** (a build-time question an engineer will hit early), **Low** (completeness). |

## 1. Summary

17 gaps: 4 High, 8 Medium, 5 Low. Two were errors in committed work (IG-1, IG-2) and are now closed, pending review. Six are missing design decisions that block or distort work packages (IG-3 to IG-9). The rest are completeness and planning items.

| Severity | Gaps |
|---|---|
| High | IG-1, IG-2, IG-3, IG-5 |
| Medium | IG-4, IG-6, IG-7, IG-8, IG-9, IG-11, IG-14, IG-15 |
| Low | IG-10, IG-12, IG-13, IG-16, IG-17 |

## 2. Gap register

Owner roles use the glossary in `docs/governance.md`. "Close by" names the gate or package by which the gap should be resolved.

| ID | Severity | Gap | Evidence | Recommendation | Owner role | Close by |
|---|---|---|---|---|---|---|
| IG-1 | High | The plan states that all 41 Phase 1 requirements are covered, but 42 exist. FR-MCP-4 (filtered, hash-checked tool discovery) is missing from the traceability table. The generator and the new checker rule both read the phase from a fixed column, and the FR-MCP table has a different layout, so both skip it and the check passes while the plan is wrong. | Plan Section 11; `scripts/check_docs.py` rule 14; spec Section 4.12 | Make both parsers find the phase cell by pattern, add FR-MCP-4 under WP-1.9, correct the stated count, and add a negative test for a differently shaped table | Delivery lead with security engineer | **Closed, pending review** (plan v0.2): FR-MCP-4 added to Section 11 (42 requirements); `scripts/check_docs.py` finds the phase cell by pattern, checks the stated count, and was shown to fail when the row is removed. Other generated tables were not audited for the same layout assumption. |
| IG-2 | High | Schema freeze is scheduled inconsistently. Section 3 says freeze at the end of week 2, and the weeks 1 to 2 milestone says "schema freeze", but WP-1.5 (schema) runs in weeks 3 to 4 and WP-1.6 depends on it. | Plan Sections 3, 6.3 and WP-1.5 | Start WP-1.5 in week 1 on lane A and move WP-1.1 and part of WP-1.2 to other lanes, or move the freeze to week 4 and shift dependent packages; update the critical path text | Delivery lead | **Closed, pending review** (plan v0.2): WP-1.5 starts in week 1 on lane A, its dependency on WP-1.2 removed, ADR-4 must be decided by the end of week 1, roles and constraint tests finish in weeks 3 to 4; baseline and configuration work moved to other lanes. Lane load at the high estimate was not rechecked (IG-15 remains open). |
| IG-3 | High | Upstream forwarding is undefined. The thin gateway "allows or denies", but AC-3 needs a granted call to reach an MCP server and FR-DRIFT-2 needs the gateway to fetch the upstream `tools/list` on every list. The plan does not say whether the gateway proxies `tools/call`, which transports are in scope, how it connects upstream (each connection needs the SSRF guard per FR-SSRF-1), or how it authenticates upstream while the broker is a Phase 2 item and the design forbids long-lived upstream secrets. | Plan WP-1.9; spec FR-DRIFT-2, FR-SSRF-1; architecture Section 5 | Add a design note to WP-1.9: Streamable HTTP only, gateway proxies calls to registered servers through the SSRF-guarded client, fixtures use no upstream credential, and a rule that no static upstream secret is stored (broker in Phase 2); record which of the 14 pipeline stages exist in Phase 1 | Security architect with backend engineer | Before WP-1.9 starts |
| IG-4 | Medium | Outbound fetches that must pass the SSRF guard are missed: identity-provider discovery and key-set fetches by the gateway and API. The plan treats the guard as covering registration, import and health checks only, and does not say how an internal identity provider gets an allowlist entry with owner and expiry (FR-SSRF-5). | Plan WP-1.3, WP-1.10; spec FR-SSRF-1, FR-SSRF-5 | Add identity-provider fetches to the guard's client wrapper requirements and define the exception entry for the development Keycloak | Security engineer | Before WP-1.10 |
| IG-5 | High | The path from gateway decisions to the audit chain is undefined. The gateway has no database. WP-1.9 says "audit events for decisions" without a transport, buffering or failure behaviour, and the plan places audit inside `api`, while architecture Section 4.8 describes a separate audit service that receives events from all services through an outbox. FR-AUD-1 requires an event for every allow or deny. | Plan Section 4.1, WP-1.4, WP-1.9; architecture Section 4.8; `docs/cross-cutting-design.md` Section 4 | Decide in a short design note: where chain writing lives in Phase 1 (module in `api` or a small separate service), how the gateway submits events (authenticated endpoint plus local bounded buffer), what a full buffer does (deny, per the design), and update Section 4.1 to state the difference from the architecture | Security architect | Before WP-1.4 and WP-1.9 start |
| IG-6 | Medium | Scanner job dispatch is undefined. Redis and Kafka arrive in Phase 2. The plan does not say how imports are queued (for example a database job table), how the scanner authenticates to the API, how results are written back, or how isolation is enforced (process, container, network). | Plan Section 4.1, WP-1.7; roadmap Section 6.1 "Not in Phase 1" | Specify a database-backed job table with claim and timeout semantics, a machine identity for the scanner, and the isolation boundary and its test | Backend engineer | Before WP-1.7 |
| IG-7 | Medium | The effect time of registry changes at the gateway is unstated. The gateway cache is 60 s while containment is specified within 5 s (PAR-F-01). Phase 1 acceptance only says "by the next `tools/list`", and the plan does not say how quarantine or revocation reaches the gateway before cache expiry. | Plan WP-1.9; `docs/parameter-register.md` PAR-F-01, PAR-F-02; AC-2 | State the Phase 1 guarantee explicitly (cache TTL bound) and the Phase 2 mechanism (change events), and add a test that measures the actual delay | Backend engineer | Before WP-1.9 |
| IG-8 | Medium | The set of hashed definition fields is not listed. The plan names the canonical form but not which tool and resource fields are included (name, title, description, input and output schema, annotations, icons), how unknown extra fields are treated, or whether per-authorization-context lists are hashed separately. | Plan WP-1.2, WP-1.9; spec FR-DRIFT-1; `docs/mcp-compatibility.md` Section 3A | Add a field list and an unknown-field rule to WP-1.2, with test vectors for each field changing | Security engineer | Before WP-1.2 completes |
| IG-9 | Medium | Row-level security with connection pooling has no design or test. The usual failure is a tenant setting that leaks between requests on a pooled connection. | Plan WP-1.5, WP-1.6; `docs/data-model.md` Sections 3 and 5 | Specify per-transaction tenant setting, forbid session-level state, and add a test that runs interleaved requests for two tenants on one pooled connection | Backend engineer | Before schema freeze |
| IG-10 | Low | The ADR-3 row says the approval queue is "bound to the argument hash". That was copied from the architecture default. Call-time approvals are outside Phase 1, so the Phase 1 approval is of tool definitions and agent registrations. | Plan Section 3; roadmap Section 6.1 "Not in Phase 1" | Correct the wording | Delivery lead | Next plan version |
| IG-11 | Medium | Acceptance criteria are not mapped to work packages in a table. AC-1 to AC-9 appear only inside package text, and non-functional requirements and threats have no mapping at all. | Plan Sections 5 and 11 | Add a generated table: AC to test cases to owning package, and list which NFRs have Phase 1 content (for example NFR-9) | Test lead | Next plan version |
| IG-12 | Low | Control-to-package links are prose only, so the checker cannot verify them. | Plan Section 11 last paragraph | Turn the paragraph into a table generated from `controls/catalogue.yaml` phases, and check that each control with Phase 1 content has a package | Delivery lead | Next plan version |
| IG-13 | Low | No package covers documentation and operations material: API reference, developer onboarding, the Phase 1 runbook sections the acceptance criteria rely on. WP-1.13 mentions an exercise but nothing produces the procedures. | Plan WP-1.13; `docs/runbooks/operational-runbook.md` | Add documentation tasks to the owning packages and a runbook update task to WP-1.13 | Platform operator | Next plan version |
| IG-14 | Medium | No security review of the build design is scheduled. The invariants are security-critical, but the plan has no threat-model walk-through of the code design, no named reviewer (an independent reviewer is required by the governance document) and no review of fuzzing results before acceptance. | Plan Sections 2, 5, 8; `docs/governance.md` Sections 1 and 4 | Add review checkpoints: design review after IG-3 and IG-5 notes, code review rules for `common` and policy, and an independent review before the acceptance run | Security architect | Before WP-1.9 starts |
| IG-15 | Medium | Lane load is unbalanced. At the high estimates, lane A carries about 15 person-weeks (WP-1.1, 1.2, 1.4, 1.5, 1.6) in about 10 weeks for one engineer. Lane D carries the harness, the dashboard and DevSecOps with part-time people. The plan states no capacity per lane. | Plan Sections 6.1 and 6.3 | Add per-lane capacity and totals; rebalance, or state which packages slip first | Delivery lead | Before dates are committed |
| IG-16 | Low | The dependency graph is incomplete. There is no edge from WP-1.5 to WP-1.4 (the text says audit storage depends on it), no ADR-3 edge to the dashboard, and the spike nodes are not linked to the design steps they gate beyond S5 and S3. | Plan Section 6.2 and WP-1.4, WP-1.11 | Add the edges, and keep the graph in step with the text | Delivery lead | Next plan version |
| IG-17 | Low | The seeded fleet and several tooling decisions are unspecified: the seed data that TC-Z7 and AC-6 need, coverage thresholds, the migration tool and the database access layer. | Plan WP-1.12, Sections 4.3 and 7 | Add a seed definition to WP-1.12; record the open tool choices as parameters or decisions | Test lead, backend engineer | Before the respective package starts |

## 3. Suggested fix order

1. IG-1 and IG-2 (done in plan v0.2, pending review).
2. IG-3, IG-5, IG-14 (design notes and review checkpoints that gate WP-1.4 and WP-1.9).
3. IG-4, IG-6 to IG-9 (decisions inside individual packages).
4. IG-10 to IG-13, IG-15 to IG-17 (completeness and planning).

## 4. Relation to other registers

- Roadmap findings F1 to F8 in `docs/roadmap.md` Section 9 and the design gaps in `docs/reviewgap.md` are separate and are not repeated here.
- If IG-1 shows that other generated tables rely on column positions, add the same pattern-based parsing to those scripts.

## 5. Change history

| Version | Date | Change |
|---|---|---|
| 0.3 | 2026-11-22 | Low gaps incorporated in implementation plan v0.3 (Section 6) |
| 0.2 | 2026-11-22 | IG-1 and IG-2 incorporated in implementation plan v0.2 and the checker |
| 0.1 | 2026-11-22 | First version: 17 gaps found when reviewing implementation plan v0.1 |

## 6. Closure update for the Low gaps (plan v0.3)

All five are "closed, pending review": changed by the author, not yet reviewed by someone else.

| Gap | Status | What changed | Where | Remaining |
|---|---|---|---|---|
| IG-10 | Closed, pending review | ADR-3 row says the Phase 1 approval covers tool definitions and agent registrations; call-time approvals are outside Phase 1 | Plan Section 3 | None |
| IG-12 | Closed, pending review | Control-to-package paragraph replaced by a table; `check_docs.py` fails if a control with P1 in its phase has no row, a row names an unknown control or package, or the phase differs from the catalogue (negative case tried by deleting a row) | Plan Section 11, `scripts/check_docs.py` | The table is maintained by hand, not generated; the check verifies it |
| IG-13 | Closed, pending review | Documentation tasks added to WP-1.1 (onboarding), WP-1.5 (data model, decisions), WP-1.6 (API reference), WP-1.9 (operator notes); WP-1.13 now updates the runbook and replaces Phase 1 `[TBD]` items | Plan WP-1.1, 1.5, 1.6, 1.9, 1.13 | No effort added to the estimates; re-check at the re-baseline |
| IG-16 | Closed, pending review | Edges added: WP-1.5 to WP-1.4, ADR-3 to WP-1.11, ADR-6 to WP-1.8; text states which spikes gate which package and that S1, S2, S4 and S6 have no Phase 1 edge | Plan Section 6.2 | Diagram not rendered after the change (the checker validates structure only) |
| IG-17 | Closed, pending review | Seed fleet proposal in WP-1.12; coverage thresholds, migration tool and access layer recorded as PAR-O-26..28 | Plan WP-1.12 and Section 4.3; `docs/parameter-register.md` v0.2 | Tool and threshold values still undecided; seed counts are proposals |

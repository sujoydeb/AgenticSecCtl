# Decision Brief: ADR-3, ADR-4 and ADR-6 (Phase 0 exit)

| | |
|---|---|
| Version | 0.1 (decision brief; recommendations only, **nothing is decided**) |
| Date | 2026-11-22 |
| Depends on | `Plan/functional-spec.md` v0.7 (FR-POL-1, FR-AUTHZ-8..11, FR-UI-3, Section 12), `Plan/architecture.md` v0.5 (Section 12), `Plan/implementation-plan.md` v0.6 (Sections 3, 4.4, WP-1.5, WP-1.8, WP-1.11), `docs/data-model.md` v0.2, `docs/deployment-architecture.md` v0.4 (Section 9), `docs/tech-evaluation.md` v0.2 (Section 3.4), `docs/authn-authz-design.md` v0.1, `docs/roadmap.md` v0.4 (Sections 4 and 5), `docs/governance.md` v0.4 (Sections 5 and 8), `docs/customer-inputs.md` v0.2 |
| Purpose | Put the three decisions that gate Phase 1 in front of the people who must make them: what each choice is, what it changes in the plan, what is recommended and why, and what would change the recommendation. Closes nothing by itself; the decision is recorded in `docs/governance.md` Section 5. |
| Audience | Sponsor, security architect, product owner. Each decision names its decider below. |
| Status | The recommendations are the drafter's judgement from the design documents. Nothing here was run or measured: no SQL, Rego or integration has been executed, and the technology facts are those in `docs/tech-evaluation.md`, much of which is unverified. |

## 1. What is being decided, and why now

Phase 1 cannot start cleanly until these three are decided (`docs/roadmap.md` Section 5 and finding F5; checklist rows P0-07, P0-08 and P0-09 in `docs/governance.md` Section 8).

| ADR | Question | Decider (proposed) | Needed by | What stops without it | Checklist row |
|---|---|---|---|---|---|
| ADR-4 | Tenancy model | Security architect, with the sponsor | Before the schema freeze at the end of week 2 of Phase 1; proposed due week -2 | WP-1.5 schema and row-level security; WP-1.6 API | P0-07 |
| ADR-3 | Approval channel | Product owner | Before the dashboard UI freeze; proposed due week -1 | WP-1.11 dashboard approval queue | P0-08 |
| ADR-6 | Policy language | Security architect | Before WP-1.8 starts; proposed due week -3, after the policy-latency spike S3 | WP-1.8 policies and the policy client in WP-1.9 | P0-09 |

The decider column follows the owners named in `Plan/architecture.md` Section 12 (security architect and product owner); no person holds either role yet (`docs/governance.md` Section 3).

## 2. ADR-4: tenancy model

**Question.** Does each customer get its own deployment, or do customers share one deployment with isolation inside it?

| Option | What it means | Phase 1 effect | Trade-off |
|---|---|---|---|
| A. Shared deployment, logical isolation (**recommended**) | Tenant ID on every row, PostgreSQL row-level security as the second line behind application filters, per-tenant policy bundles | The plan as written: WP-1.5 and WP-1.6 | Cheapest to run and build; a bug in isolation exposes every tenant (the weakest blast-radius separation of the three) |
| B. Dedicated namespace and database per tenant on a shared cluster | Network policy plus a separate database and keys per tenant | Same tables and tenant ID; adds deployment and operations work (`docs/deployment-architecture.md` Section 9) | Stronger isolation for regulated tenants; more to operate; nodes still shared |
| C. Dedicated cluster, account or project per tenant (or single tenant per deployment) | Full separation including nodes and key management | Same code; the deployment work is the cost | Highest assurance and cost; many deployments to patch and monitor |

**Recommendation: A, with tenant ID on every table so that B stays a deployment decision rather than a schema change.** This is the default in `docs/deployment-architecture.md` Section 9, `docs/data-model.md` and the customer-input assumption CI-3. Isolation must pass the cross-tenant tests (TC-I3) in every model, so choosing A does not lower the test bar.

**What the decider is accepting.** A larger blast radius if row-level security or the application filters fail. The plan's mitigations are database role design (no superuser, no `BYPASSRLS`), the tenant set per transaction and never per session, and the interleaved-tenant test on a pooled connection (WP-1.5, IG-9). These are designs, not results: the data-model SQL has not been run on PostgreSQL (checklist row P0-19). Accept A conditionally on that test passing.

**What would change the recommendation.** A first customer that requires a dedicated database or a sovereign deployment at launch (customer input CI-3), or a regulator or contract that rules out shared databases. Then B or C is chosen for that customer, and the Phase 1 code stays the same; per `Plan/implementation-plan.md` Section 3 the dedicated-database option adds deployment work, not tables. Per-tenant key hierarchy (FR-ADM-2) is a Phase 5 item under any option.

**Cost of deciding late or wrongly.** Late: the schema freeze slips and every package that reads the registry waits. Wrong in the stricter direction (A chosen, B needed) is a deployment project; wrong in the looser direction (C chosen, shared deployment wanted) costs operating effort and money but no rewrite. These are judgements, not measurements.

## 3. ADR-3: approval channel

**Question.** Where do approvers approve: in the platform's own dashboard, or through a ticketing or chat system (the architecture names ServiceNow and Slack)?

| Option | Phase 1 effect | Trade-off |
|---|---|---|
| A. Dashboard approval queue only (**recommended**) | WP-1.11 as written: approval queue with diff and evidence; separation of duties enforced by the API | Fewest moving parts; approvers must use another tool; no external audit trail from the ticketing system |
| B. Dashboard first, webhook adapters to ticketing and chat later | Same Phase 1; adapters are Phase 2 or later (`Plan/implementation-plan.md` Section 3) | Same as A, and keeps the option open |
| C. Ticketing or chat integration from the start | Adds adapter design, mapping of the external user to a platform identity, authenticity of callbacks and step-up authentication to Phase 1; not estimated in the plan | Matches how some enterprises already work; widens the attack surface of the approval step and is where approval fatigue and spoofed approvals appear (threat X14, FR-AUTHZ-9..11) |

**Recommendation: A in Phase 1, with B as the stated path** (customer-input assumption CI-2). What Phase 1 approves is tool definitions and agent registrations (the plan, IG-10); call-time approvals bound to the argument hash and step-up authentication (FR-AUTHZ-9..11) are Phase 2 requirements, so the harder channel questions can wait until they are needed. Whatever channel is chosen, separation of duties stays server-side: the API refuses self-approval and the interface only hides buttons (invariant in plan Section 2; TC-E4, TC-Z7).

**What would change the recommendation.** A customer who will not use a new approval tool, or a compliance rule that approvals must be recorded in the ticketing system. Then C moves into scope and the plan needs a new package and a larger estimate.

**A wording fix to make when this is decided.** The ADR-3 row of `Plan/architecture.md` Section 12 says the queue is "bound to argument hash". That describes call-time approval (Phase 2). For Phase 1 the approval is of definitions and registrations; the architecture row should say so. This is the same correction already made in the implementation plan.

## 4. ADR-6: policy language

**Question.** Are authorization policies written in Rego and evaluated by OPA, or in Cedar?

| Option | Facts from the repository | Trade-off |
|---|---|---|
| A. Rego on OPA (**recommended**) | FR-POL-1 already requires Rego, versioned in source control and tested with `opa test` in CI. OPA is a CNCF graduated project (verified in `docs/tech-evaluation.md`); its licence is still to be confirmed from the repository. Decision logs and bundles are built in, and later requirements (signed bundles, shadow mode: FR-POL-3, FR-POL-4) rely on bundles. An illustrative Rego sketch exists in `docs/authn-authz-design.md` but has never been run | Rego has a learning curve; the team needs Rego skills |
| B. Cedar | Marked **[VERIFY]** in the technology evaluation: libraries are mainly Rust, Python binding maturity is unknown, and decision logging and bundles would be the platform's own work. Its strength is formal analysis of policies | Smaller ecosystem here; replacing Rego means changing the specification (FR-POL-1), WP-1.8 and the policy client in WP-1.9 |

**Recommendation: A, conditional on spike S3.** The decision should be taken after S3 (policy latency, weeks -5 to -4), which measures decision latency with realistic data against NFR-1 and informs the cache design. If S3 shows Rego cannot meet the latency budget with a decision cache, revisit; otherwise confirm A. The technology evaluation's own provisional recommendation is OPA and Rego for the MVP, revisiting Cedar only if formal analysis becomes a requirement.

**What the decider is accepting.** Rego skills as a team dependency and the unexecuted state of the sketch: `opa test` has not been run on any policy in this repository (checklist row P0-16 asks for that).

**What would change the recommendation.** A requirement to prove properties of policies formally, a team that already runs Cedar, or an S3 result that rules Rego out. Choosing B is not a Phase 1 shortcut: it changes FR-POL-1 in the specification, so the spec owner must be part of that decision.

## 5. Decisions requested

Record each in `docs/governance.md` Section 5 with the decider's name and date, and update the "Proposed resolution" wording there.

| ADR | Recommended resolution | Condition | Decider | Record |
|---|---|---|---|---|
| ADR-4 | Shared multi-tenant with row-level security and tenant ID on every table; dedicated database or cluster models remain deployment options | Customer input CI-3 confirms no tenant needs a dedicated database at launch; the interleaved-tenant test (P0-19) passes | Security architect, with the sponsor | Decision log row ADR-4; plan Section 3 unchanged |
| ADR-3 | Dashboard approval queue for definitions and registrations in Phase 1; webhook adapters to ticketing and chat later | Customer input CI-2 confirms | Product owner | Decision log row ADR-3; correct the wording in `Plan/architecture.md` Section 12 |
| ADR-6 | Rego on OPA | Spike S3 result does not rule it out; OPA licence confirmed | Security architect | Decision log row ADR-6 |

A decision with a condition is recorded as "decided, conditional" with the condition and its due week; the plan treats an unmet condition like an open decision for the packages it gates.

## 6. What this brief does not settle

- ADR-1, ADR-2, ADR-5 and ADR-7 are not needed for Phase 1; they need an owner and a date (checklist row P0-10), not a decision.
- The Phase 1 gateway design notes (`Plan/implementation-plan.md` Section 4.4) are a separate decision for review checkpoint R1 (row P0-12).
- The hashed definition field list (row P0-13) and the B1 parameter values (row P0-20) are separate decisions with their own owners.
- It does not name the people. Until the sponsor, security architect and product owner roles are filled (rows P0-01 and P0-02), these decisions have no one to take them.

## 7. Evidence and limits

- Everything above comes from the documents named in the header table. No option was tested; no product was evaluated here beyond what `docs/tech-evaluation.md` records.
- The cost comparisons are qualitative. The plan does not estimate an adapter package for ADR-3 option C or a deployment package for ADR-4 options B and C.
- The recommendations are those of the drafter (an AI assistant working from the repository) and are for the named deciders to accept, change or reject.

## 8. Change history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-11-22 | First version |

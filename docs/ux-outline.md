# Dashboard UX Outline

| | |
|---|---|
| Version | 0.1 (outline; closes gap A7 in `docs/reviewgap.md`) |
| Depends on | `Plan/functional-spec.md` v0.8 (FR-UI-1..7, FR-AUTHZ-9..11, FR-DATA-*, NFR-10), `docs/api-specification.md` v0.4, `docs/prd.md` v0.4 (personas, Section 7 user stories), `controls/catalogue.md` v0.6 (CTL-28), `docs/testing/cases.md` v0.5 (TC-Z7..Z9, TC-Z21, TC-X14, TC-Z33) |
| Status | Information architecture and flow outline. **No visual design, wireframes or user research.** Screens are described in words; layout, components and copy still need design and usability testing with the personas. |

## 1. Principles

1. **Show evidence, not conclusions:** every score, status and recommendation links to the finding, diff, event or policy decision behind it.
2. **Safe by default:** destructive or high-impact actions show their exact effect first; nothing is approved from a list view; approval screens are separate and read-only until the approver acknowledges what they see.
3. **Untrusted text is inert:** tool descriptions, responses, error text and agent summaries are rendered as plain text in a labelled "untrusted content" area, never as HTML, never auto-fetching links or images (TC-X5, TC-Z29).
4. **Roles shape the view:** viewers, engineers, approvers and auditors see different actions; the API, not the UI, enforces rights and separation of duties.
5. **Honest about coverage:** show known gaps (unmanaged endpoints, stale data) wherever counts are shown.
6. **Accessible:** WCAG 2.1 AA on core flows (NFR-10, TC-Z21), keyboard operable, readable in light and dark themes, usable on narrow screens for approvals.

## 2. Information architecture

| Area | Screens | Primary personas | Requirements |
|---|---|---|---|
| Overview | Fleet summary tiles (agents, servers, tools, approved or not, quarantined, critical and high findings, drift events), coverage-gap banner, recent incidents | CISO, security engineer | FR-UI-1, FR-INV-7 |
| Inventory | Agents, servers, tools lists with filters (owner, environment, criticality, classification, status); detail pages | Owners, engineers | FR-UI-2, FR-INV-* |
| Findings and scans | Findings list by severity and status; scan detail with rule-set version and evidence | Security engineer | FR-SCAN-2, FR-UI-1 |
| Approvals | Queue (mine, pending, decided); approval detail (diff, evidence, arguments, hash) | Approver, engineer | FR-UI-3, FR-AUTHZ-9..11 |
| Drift | Quarantined tools, field-level diff between approved and current, history | Security engineer | FR-DRIFT-3..5 |
| Access | Permissions, grants (static and JIT), expiries, unused and excessive permissions, delegation chains | Owners, engineers | FR-AUTHZ-6, 7, FR-UI-5 |
| Relationship graph | Agent, model, server, tool, data source, enterprise system; filters; classification shown | CISO, architects | FR-INV-6, FR-UI-5 |
| Operations | Authentication failures, blocked operations, leakage attempts, limits, active incidents | Security on-call | FR-UI-4 |
| Incidents | Incident list and detail, containment actions, evidence index, timeline | Incident responder | FR-IR-* |
| Compliance | Control status, mappings (mandatory, guidance, voluntary shown separately), evidence packs | Auditor, compliance liaison | FR-UI-6, FR-COMP-* |
| Administration | Roles, tenants, notification channels, classification levels, configuration history, break-glass use | Security admin | FR-ADM-*, FR-DATA-1 |

## 3. Key flows

### 3.1 Tool approval
1. Owner registers a server; the platform shows import and scan progress and any rejected URL with the reason.
2. Reviewer opens the approval: summary header (tool, server, owner, action class, classification), findings with evidence, diff to the previous version, destination allowlist, requested permissions.
3. Reviewer sets or confirms the action class and classification, acknowledges Critical or High findings individually, and approves or rejects with a reason. A Critical override shows that a second approver is needed and who has approved so far.
4. The result shows the new version and hash; the audit event link is shown.

### 3.2 Drift response
A banner on the overview and a drift list show quarantined tools. The detail page shows the field-level diff first, then calls made since the last approval, then actions: re-scan, approve new version (new approval flow), reject, contact owner.

### 3.3 High-impact call approval
Approval detail shows, in this order: who asked (agent, owner), what will happen (tool, action class, resource, platform-rendered arguments and their hash), data involved (classification, taint state), why the platform asks (policy reason), and the agent's own text in a labelled untrusted area. Approval requires step-up authentication; bulk approval is not offered; very fast approvals raise a warning to the approver and an alert (FR-AUTHZ-9..11).

### 3.4 Incident containment
From any asset page, "Quarantine", "Revoke credentials" and "Suspend" are available to permitted roles, each with a confirmation showing blast radius (affected agents and sessions), a reason field and the evidence snapshot status; the screen shows the time to effect and confirms with a test result when possible.

### 3.5 Audit and evidence
Auditors select a control and period, see the evidence index, generate a pack, and verify its hash list; chain verification status and last anchor time are visible. Raw evidence is not shown here (vault roles only).

## 4. Content and terminology

Use the glossary in the specification and `docs/governance.md`; show IDs (FR, CTL, TC) only in auditor and engineer views; plain wording for approvers. Severity and status colours are never the only signal.

## 5. States and edge cases

Empty states explain what to do next; loading and stale states show data age; permission-denied states do not reveal other tenants' objects; failure states show the correlation ID; the UI works when the notification channel is down.

## 6. Open items

- Visual design, wireframes and a clickable prototype (design skills and tools to be chosen).
- Usability tests with owners, engineers, approvers, auditors and responders.
- Decide whether the first release supports mobile approvals (affects session security).
- Define the data refresh model (polling versus push) and maximum staleness (parameter register).
- Localisation and accessibility audit scope beyond core flows.

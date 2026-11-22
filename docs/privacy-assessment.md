# Platform Privacy Assessment (data inventory and risks)

| | |
|---|---|
| Version | 0.1 (draft for review by privacy and legal; closes the analysis part of gap H2 in `docs/reviewgap.md`) |
| Depends on | `Plan/functional-spec.md` v0.5 (FR-AUD-3, FR-DATA-*, FR-ADM-4, FR-ADM-5, FR-ADM-7, FR-ADM-8, NFR-6), `docs/data-model.md` v0.1, `docs/deployment-architecture.md` v0.3 (Section 6), `docs/cross-cutting-design.md` v0.1, `compliance/compliance-matrix.md` v0.4 (Section 6), `controls/catalogue.md` v0.3 (CTL-10, CTL-22, CTL-29) |
| Not legal advice | Whether the platform's processing needs a formal impact assessment, which legal bases apply, who is controller or processor, and transfer mechanisms are legal determinations; none is made here. Statements about legal duties are questions for legal, tagged **[LEGAL]**. |
| Status | Analysis of the *design*. Nothing is implemented; data fields may change at schema freeze. |

## 1. Purpose and scope

The platform exists to protect other systems' data, but it also stores information about people and about customer data. This assessment lists what it stores, why, for how long, who can see it, and the risks and mitigations, so privacy requirements are visible before schema freeze. It covers the platform's own processing, not the privacy duties of the agents and systems it protects (compliance matrix Section 6).

## 2. Data inventory

| Data | Examples | Personal data? | Purpose | Where | Retention (placeholder) | Access |
|---|---|---|---|---|---|---|
| User identity | IdP subject, name, email, roles | Yes | Authentication, accountability (who approved) | Registry (`users`, `role_bindings`) | Life of account plus audit period | Admins, auditors (read) |
| Agent and owner records | Agent names, owner subject, environment | Indirectly (owner) | Inventory, ownership | Registry | Life of asset plus audit period | Roles per RBAC |
| Audit events | Actor, decision, subject IDs, digests, redacted excerpts | Yes (actor; excerpts may include personal data) | Accountability, reproducibility, evidence | Audit store, SIEM export | 13 months hot, 7 years cold (placeholder, NFR-6) | Auditors, security roles; operators no raw access |
| Raw evidence | Request or response captures for incidents | Possibly, including customer personal data | Incident investigation | Evidence vault (encrypted) | Per case and legal hold | Named incident roles with reason (FR-ADM-8) |
| Redacted excerpts | Short snippets in findings and events | Possible residual personal data | Explain decisions | Registry and audit | Same as parent record | Roles per RBAC |
| Tool definitions and scan results | Descriptions, schemas, findings | Unlikely, but descriptions may contain internal names or data | Security review | Registry | Life of tool plus audit period | Roles per RBAC |
| Session summaries | Agent, time, taint, highest classification, call counts | Indirectly | Investigation, limits | Registry or session store | Short (to be set) | Security roles |
| Traffic content in transit | Tool arguments and results | Possibly customer personal data | Inspection (DLP, injection) | In memory only; digests in audit | Not stored beyond request, except redacted excerpts and evidence under incident | Processing only |
| Operational logs and traces | Structured logs, spans | Possibly via IDs | Operations | Log backend | Short (to be set) | Operators, redacted |
| Approval records | Who approved what, arguments hash, rendered arguments | Yes (approver) | Separation of duties, evidence | Registry and audit | As audit | Roles per RBAC |
| Notification contacts | Email addresses, webhook endpoints | Yes | Notifications | Registry | Life of tenant | Admins |
| Classification labels | Levels per tool, resource, data source | No | Policy | Registry | Life of asset | Roles per RBAC |

## 3. Design measures already in the specification

- Minimisation: digests and redacted excerpts instead of raw payloads in the audit store (FR-AUD-3); traffic content not stored beyond the request (design principle in `docs/data-model.md`).
- Purpose limitation and access: raw evidence only through the vault by named roles with a recorded reason; operators excluded (FR-ADM-8, SoD-3).
- Retention controls, legal hold and per-tenant configuration (NFR-6, FR-ADM-5, FR-ADM-7).
- Tenant isolation with row-level security and per-tenant keys later (FR-RT-8, FR-ADM-2, FR-KEY-6).
- Residency pinning (FR-ADM-4) and region-pinned backups and anchors (deployment architecture Section 6.4).
- Data classification so policy treats sensitive data accordingly (FR-DATA-1..4).
- Redaction in logs, traces, errors and UI (FR-AUTHN-6, TC-G5).
- External classifier or scanner services only with tenant opt-in and minimum content (FR-SCAN-8, TC-Z13).

## 4. Risks and mitigations

| Risk | Likelihood and impact (judgment) | Mitigation | Residual |
|---|---|---|---|
| Redacted excerpts still contain personal data | Medium / medium | Short excerpt limits; DLP before storing; per-tenant excerpt policy; review of excerpt design | Low-medium |
| Long retention of audit data containing personal data conflicts with storage-limitation duties **[LEGAL]** | Medium / medium | Make retention per tenant and per data class; minimise personal data in excerpts; legal review of the 7-year default (gap D5) | Depends on legal view |
| Raw evidence vault becomes a high-value personal data store | Low / high | Encryption, named roles, reason and custody records, legal hold limits, region pinning | Low-medium |
| Sending tool text to an external classifier transfers data to a third party **[LEGAL]** | Medium / medium | Opt-in per tenant, minimum content, self-hosted alternative, data processing terms before enabling | Low |
| Cross-border access by operators or support | Low / medium | Region-pinned data planes, operator no-access rule, break-glass audit | Low-medium |
| Excessive access to audit and findings by broad roles | Medium / medium | RBAC review, quarterly access recertification, auditor read-only | Low |
| Monitoring of employees through agent activity logs **[LEGAL]** | Medium / medium | Purpose statement, transparency to staff, role-based access, works-council or equivalent review where applicable | Depends on jurisdiction |
| Data subject requests (access, erasure) against audit data | Medium / medium | Define how audit immutability and erasure duties are reconciled (pseudonymise actor identifiers, retention end, or restrictions); decide with legal | Open |
| Backups and anchors keep personal data past retention | Medium / low | Backups expire on their own schedule; anchors contain only hashes | Low |
| Telemetry exports leak identifiers | Low / medium | Redaction in the collector, field allowlists | Low |

## 5. Questions for legal and privacy **[LEGAL]**

1. Role of the platform operator versus the customer (controller, processor, joint) for each data class.
2. Lawful bases and notices for processing staff identities and activity.
3. Whether a formal impact assessment is required, and its scope.
4. Retention periods for audit events and evidence per jurisdiction; reconciliation of immutability with erasure rights.
5. Rules for transfers when enabling external classifiers, SIEM exports or cloud services in other regions.
6. Contract terms for sub-processors (cloud, IdP, SIEM, classifier vendors).
7. Breach-notification triggers involving platform data.

## 6. Actions

| Action | Owner role | Gate |
|---|---|---|
| Review this inventory and risks with privacy and legal | Compliance liaison | Before Phase 1 schema freeze |
| Decide excerpt content and size limits (feeds `docs/data-model.md`) | Security engineer | Before Phase 1 |
| Decide retention per class (feeds NFR-6 and the parameter register) | Compliance liaison | Before Phase 2 |
| Decide erasure handling for audit data | Compliance liaison with legal | Before Phase 2 |
| Add data subject request procedures to the runbook | Platform operator | Phase 2 |
| Repeat the assessment when new data fields or integrations are added | Security architect | Each phase gate |

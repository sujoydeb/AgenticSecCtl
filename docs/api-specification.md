# API Specification (management plane): endpoints, roles and traceability

| | |
|---|---|
| Version | 0.1 (design draft; closes gap A3 in `docs/reviewgap.md`) |
| Depends on | `Plan/functional-spec.md` v0.4 (Section 4.21 conventions, roles in Section 2, FR rows referenced below), `Plan/architecture.md` v0.3 (Section 4.4 and Section 4.8 audit vocabulary), `docs/data-model.md` v0.1, `controls/catalogue.md` v0.2 |
| Machine-readable outline | `docs/api/openapi.yaml` (OpenAPI 3.1, **not validated with a tool, not implemented**) |
| Scope | The management API: registry, approvals, findings, incidents, audit, governance. The gateway's agent-facing MCP interface and the internal gateway-to-registry and event interfaces are not covered. |

## 1. Conventions (from the specification)

- REST and JSON under `/v1`; OpenAPI 3.1 published with the service; all list endpoints are paginated (`limit`, `page_token`), filterable and tenant-scoped.
- Authentication: OIDC bearer tokens from the enterprise IdP with MFA for people; service-to-service calls use workload identity. Authorization is role-based with resource scope plus the separation-of-duties rules enforced **in the API, not only in the UI**.
- Create and decision operations require an `Idempotency-Key` header.
- Errors use RFC 9457 problem details with a correlation ID; error bodies never contain secrets, stack traces or raw payloads; the gateway's errors toward agents are separate and minimal (FR-RT-13).
- Every state change writes an audit event (vocabulary: `Plan/architecture.md` Section 4.8) in the same transaction as the change.
- Rate limits per tenant and per caller; limits and quotas are parameters to be set.

## 2. Endpoint table

Roles use the names of spec Section 2: Viewer (V), Agent owner (AO), Server owner (SO), Security engineer (SE), Approver (AP), Security admin (SA), Auditor (AU), Incident responder (IR), Platform operator (PO). "SoD" shows the separation-of-duties rule the API enforces.

| Method and path | Purpose | Roles | SoD / rule | Requirements | Audit events |
|---|---|---|---|---|---|
| GET `/agents`, `/agents/{id}` | List and read agents | V, AO, SE, AP, AU | Tenant scope | FR-INV-1, FR-UI-1/2 | none (read) |
| POST `/agents` | Register an agent (pending) | AO | Approval by a different user | FR-INV-1, FR-ID-1/2 | `approval.requested` |
| PUT `/agents/{id}/suspension` | Kill switch | SE, IR | Reason required; effect within 5 s | FR-AUTO-4, FR-IR-2 | `session.suspended` |
| DELETE `/agents/{id}/suspension` | Resume | SE, AP, IR | Approver differs from the suspender unless emergency policy | FR-AUTO-5 | `approval.granted` |
| GET, POST `/servers` | List and register servers | V, SO, SE | URL checked by the SSRF guard first | FR-INV-1..4, FR-SSRF-1..5 | `register.denied` on rejection |
| POST `/servers/{id}/imports` | Hardened import and scan | SO, SE | Importer limits apply | FR-SCAN-1..4, 6 | `scan.completed`, `finding.created`, `import.failed` |
| GET `/tools/{id}`, `/tools/{id}/versions`, `/tools/{id}/diff` | Tool, history and diff | V, SO, SE, AP, AU | Versions immutable | FR-DRIFT-1/4/5, FR-UI-2 | none (read) |
| PUT `/tools/{id}/quarantine` | Quarantine | SE, IR | Reason required | FR-DRIFT-3, FR-IR-2 | `tool.quarantined` |
| GET `/approvals`; POST `/approvals/{id}/decision` | Queue and decide | AP, SE | Decider differs from requester; Critical overrides need two distinct approvers | FR-UI-3, FR-SCAN-4, SoD-1/2 | `approval.granted`, `approval.denied`, `override.requested`, `override.approved`, `tool.approved`, `tool.rejected` |
| GET `/findings` | List findings | V, SE, AU | | FR-SCAN-2, FR-UI-1 | none (read) |
| POST `/grants` | Request JIT grant | AO | TTL mandatory; approver differs | FR-AUTHZ-4 | `grant.created`, `grant.expired` (on expiry) |
| POST `/incidents`, `/incidents/{id}/containment` | Open incident and contain | IR, SE | Evidence snapshot before changes | FR-IR-1..3 | `incident.opened`, `tool.quarantined` and related |
| GET `/audit/events` | Query redacted events | AU, SE, IR | Excerpts only; raw evidence is not served here | FR-AUD-1/3 | none (read) |
| POST `/audit/verification` | Verify chain and anchors | AU, SE | | FR-AUD-2/4, TC-Z6, TC-Z22 | `audit.verify.failed` on failure |
| GET `/classification-levels` | Read levels | V, AO, SO | Changes are a separate admin operation | FR-DATA-1 | `classification.changed` on change |
| POST `/evidence-packs` | Generate signed pack | AU | Operators cannot read raw evidence | FR-COMP-4 | none specific |
| GET `/health` | Readiness | all (unauthenticated) | Fails when fail-closed guarantees cannot be met | FR-OBS-2 | none |

Not yet specified (to be added before the corresponding phase): configuration endpoints (FR-ADM-1), notification channels (FR-ADM-3), role bindings and break-glass administration (FR-ADM-6), data source and classification label assignment (FR-DATA-2/4), model registry (FR-MOD-1), discovery assets (FR-INV-5), compliance mappings (FR-COMP-*), incident reports (FR-IR-5).

## 3. Error catalogue (initial)

| Status | Problem type (short) | When |
|---|---|---|
| 400 | `invalid-request` | Schema violation or unknown field |
| 401 | `unauthenticated` | Missing, expired or invalid token |
| 403 | `forbidden` | Role or tenant scope missing |
| 403 | `separation-of-duties` | Requester tries to approve, or one approver tries an override that needs two |
| 404 | `not-found` | Unknown or other tenant's object (same response, no existence leak) |
| 409 | `conflict` | State changed (for example approving a tool that is already quarantined), idempotency mismatch |
| 422 | `ssrf-rejected` | Server URL blocked by the SSRF guard |
| 429 | `rate-limited` | Tenant or caller limit exceeded |
| 503 | `not-ready` | Dependency required for safe operation is unavailable |

## 4. Authorization model summary

1. The caller's roles and scopes come from the IdP token and role bindings in the registry.
2. Each endpoint declares required roles and tenant scope; the policy engine (OPA) evaluates management actions as well as gateway calls, using the same default-deny rule.
3. Object-level checks apply (an agent owner can modify only their agents), then separation-of-duties checks compare the actor with the requester or previous actor recorded on the object.
4. Decisions record the policy bundle hash and input digest in the audit event (FR-AUD-6).

## 5. Test linkage

Endpoint behaviours map to existing and new cases: TC-E4 and TC-Z7 (approval queue and SoD), TC-H1..H4 (server registration), TC-B1 (quarantine on drift), TC-Z6 and TC-Z22 (audit verification), TC-Z10 (configuration), TC-Z11 (notifications), TC-I3 (cross-tenant isolation through the API), TC-G5 (no secrets in errors and logs).

## 6. Open items

- Generate and validate the OpenAPI document with an OpenAPI linter; add examples.
- Pagination and filtering conventions per resource; default and maximum limits.
- Webhook interface for approval channels (ADR-3 proposal: dashboard first, adapters later).
- Event schema for the gateway-to-control-plane stream and the policy data endpoints (internal).
- Authentication of the dashboard (session cookies versus tokens) and step-up authentication for approvals (gap H4).

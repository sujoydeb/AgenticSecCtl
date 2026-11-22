# Cross-Cutting Design: logging, errors and configuration

| | |
|---|---|
| Version | 0.1 (design draft; closes gap A5 in `docs/reviewgap.md`) |
| Depends on | `Plan/functional-spec.md` v0.7 (FR-AUD-*, FR-OBS-*, FR-ADM-1, FR-RT-13, FR-AUTHN-6, Section 4.21), `Plan/architecture.md` v0.5 (Section 4.8 event vocabulary), `docs/data-model.md` v0.2, `docs/api-specification.md` v0.1, `controls/catalogue.md` v0.4 (CTL-13, CTL-14, CTL-27) |
| Status | Design draft. Library names and exact field lists are unverified and may change at implementation. |

## 1. Why one design

Logging, error handling and configuration cut across every service. Without one design they drift: secrets leak into logs, errors echo hostile text, audit and operational logs blur, and configuration loosens controls silently. This note fixes the rules; each service implements them through the shared `common` package.

## 2. Three kinds of record

| Kind | Purpose | Tamper evidence | Contains | Retention | Destination |
|---|---|---|---|---|---|
| Audit event | Accountability and reproducible decisions | Hash chain plus anchors | Actor, subject, decision, policy hash, input digest, redacted excerpt, tenant | Per NFR-6 and legal hold | Audit store, SIEM export |
| Operational log | Debugging and health | None | Structured service events, correlation IDs, redacted | Short, per operations policy | Log backend |
| Trace and metric | Performance and SLOs | None | Spans, counters, histograms; no payloads | Short | Telemetry backend |

Rules: nothing that must be provable goes only into an operational log; no payload content goes into any of them except redacted excerpts in audit events; a decision always produces an audit event, never only a log line.

## 3. Logging rules

1. **Structured JSON**, one object per line, with fields: `ts` (UTC), `level`, `service`, `version`, `tenant` (when known), `correlation_id`, `trace_id`, `event` (vocabulary name for audit-related records), `message` (fixed text), `attrs` (map).
2. **Levels:** error (service cannot do what it should), warn (degraded or denied by safety rule), info (state changes and lifecycle), debug (off in production; never enables payload logging).
3. **Redaction at the source:** tokens, keys, secrets, cookies, authorization headers and configured sensitive fields are replaced before the log call; a central filter is the second line of defence. Debug mode does not disable redaction (TC-G5).
4. **No untrusted free text in `message`.** Untrusted strings (tool text, server errors, agent input) go in `attrs`, length-limited and escaped (newlines, ANSI and control characters, quote characters) so they cannot forge records (FR-AUD-5, TC-X5, TC-Z29).
5. **Correlation:** a correlation ID is created at the gateway, carried to the registry, PDP, broker and audit service, and returned to callers in error bodies.
6. **Sampling:** low-value info logs may be sampled; audit events, security denials and errors are never sampled or dropped (a full buffer denies high-impact calls, FR-AUD-7).
7. **Time:** services use synchronised clocks; audit time comes from the database or audit service, not the caller.

## 4. Audit events

Event names come from the vocabulary in `Plan/architecture.md` Section 4.8; new names are added there first. Each event carries: tenant, sequence, time, event type, actor identity, subject type and ID, decision, policy bundle hash, input digest, payload digest, redacted excerpt (bounded size), previous hash and hash. Events are produced through the outbox in the same transaction as the state change they describe. Events produced by the gateway, which has no database, are submitted in batches to an authenticated API endpoint and chained by the API; the gateway buffers them in a bounded queue and denies calls that would be allowed when the queue is full (Phase 1 design note in `Plan/implementation-plan.md` Section 4.4).

## 5. Error handling

| Audience | Format | Content rules |
|---|---|---|
| Management API callers | RFC 9457 problem details (`type`, `title`, `status`, `detail`, `correlation_id`) | No stack traces, secrets, SQL, internal hostnames or raw payloads; not-found and forbidden for other tenants' objects look identical |
| Agents calling the gateway | MCP error responses with fixed catalogue messages ("tool unavailable", "not permitted", "limit reached") and a correlation ID | Never explain policy internals; never echo untrusted text (FR-RT-13); no hints that help probing |
| MCP servers (from the gateway) | Fixed protocol errors | No internal details |
| Operators | Logs and traces with the same correlation ID | Full detail within redaction rules |

Rules: fail closed (an unexpected exception on a security path is a denial, not a pass); translate internal errors at the edge into the catalogue; map each catalogue entry to one stable code so denials can be counted; retries only for idempotent operations with bounded backoff; panics and unhandled exceptions produce an error log, a metric and, on a security path, a denial.

Error catalogue seeds: `invalid-request`, `unauthenticated`, `forbidden`, `separation-of-duties`, `not-found`, `conflict`, `ssrf-rejected`, `rate-limited`, `not-ready`, plus gateway-side `tool-unavailable`, `not-permitted`, `limit-reached`, `approval-required`, `unsupported-version`.

## 6. Configuration management

1. **Declarative and typed:** configuration is defined by typed models (Pydantic settings in the Python services), loaded from files and environment, validated at start; unknown keys, wrong types and out-of-range values stop the service or keep the last valid configuration (TC-Z10).
2. **Layering (lowest to highest precedence):** built-in safe defaults, file in the repository per environment, environment variables from the deployment, secrets references resolved at run time. Secrets are references to the secrets manager, never values in files or images.
3. **Safety bounds in code:** some parameters have hard limits that configuration cannot exceed (for example access token lifetime maximum, redirect hops maximum, delegation depth maximum); loosening beyond a bound requires a code change reviewed under the secure-development control (CTL-27).
4. **Security-relevant settings are policy, not config:** fail-open allowlists, override rules, retention and classification settings change only through the audited management API and policy process, with the approvals in the runbook change classes.
5. **Versioning and audit:** each applied configuration has a content hash and version in `config_versions`; changes write `config.changed` with actor and diff summary; drift between declared and running configuration is detected.
6. **Parameters:** every tunable value is listed in `docs/parameter-register.md` with owner and decision gate; code defaults must match the register.
7. **Environments:** the same artifact runs in all environments; only configuration differs; production configuration is not reachable from lower environments.

## 7. Observability

OpenTelemetry for traces and metrics (GenAI conventions only after their maturity is verified); service-level metrics for decisions by reason, latency by pipeline stage, queue depths, cache ages and bundle age; dashboards and alerts per the runbook Section 4. Telemetry carries no payloads or secrets.

## 8. Testing the rules

| Rule | Test |
|---|---|
| Redaction under error and debug | TC-G5 |
| No log forgery or script execution from hostile text | TC-X5, TC-Z29 |
| Errors echo nothing untrusted | TC-X11 |
| Configuration validation and audit | TC-Z10 |
| Audit capacity and denial | TC-Z23 |
| Decision replay | TC-Z20 |

## 9. Open items

- Choose logging and tracing libraries and the redaction filter design (unverified).
- Define the audit event schema fields and size limits (with `docs/data-model.md`).
- Define the full error catalogue with stable codes and the mapping to gateway error responses.
- Decide log retention and access rules for operational logs (privacy assessment, gap H2).

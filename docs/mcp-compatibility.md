# MCP Specification Compatibility Matrix

| | |
|---|---|
| Version | 0.1 (closes the pinning part of gap E3 in `docs/reviewgap.md`) |
| Depends on | `Plan/functional-spec.md` v0.6 (FR-MCP-1..12, FR-AUTHN-*, A5, A6), `Plan/architecture.md` v0.5 (Section 4.1), `controls/catalogue.md` v0.4 (CTL-05, CTL-18), `docs/testing/cases.md` v0.5 (TC-P1..P4, TC-Z27, TC-Z28) |
| Reference revision | **2026-07-28** (pinned) |
| Evidence | The authorization, transport (overview, stdio, Streamable HTTP), sampling, elicitation and roots pages for revision 2026-07-28 were read on 2026-11-22 through a page-fetching assistant (so the quotations are paraphrases, not verbatim copies). Pages not read: client ID metadata document details, dynamic client registration request format, authorization-server-discovery and client-registration sub-pages, tools, resources, prompts and lifecycle pages, and every other revision. Re-read the primary text before relying on any row. |
| Review | Not reviewed by a second person. |

## 1. How to use this matrix

The platform pins one protocol revision at a time (FR-MCP-2, FR-MCP-12). On every new revision: read the changelog, update the rows below, run TC-P1..P4 and the authorization cases, then add the revision to the gateway's allowlist for canary tenants first (runbook Section 9.4). The matrix records what the specification says and how the platform responds; where the specification says SHOULD or leaves a choice, the platform may be stricter.

## 2. Authorization

| Specification statement (2026-07-28) | Strength | Platform response | Requirement / control / test |
|---|---|---|---|
| Authorization is optional for MCP implementations; HTTP transports should follow the authorization specification; stdio should not and takes credentials from the environment | OPTIONAL / SHOULD / SHOULD NOT | The gateway enforces authentication and authorization itself and never relies on servers doing so | A6 in the spec; FR-AUTHN-1..7; CTL-05 |
| Authorization is based on an OAuth 2.1 draft (draft-ietf-oauth-v2-1-13) | — | Gateway validates tokens per OAuth 2.1 rules; track the draft's status | FR-AUTHN-1 |
| Clients must send the `resource` parameter (RFC 8707) in authorization and token requests, identifying the server by canonical URI | MUST | Audience binding at the gateway; agents are tested for sending `resource`; token audience is checked on every request | FR-AUTHN-1; TC-G2 |
| Servers must implement protected resource metadata (RFC 9728); clients use it to discover the authorization server | MUST | Gateway exposes its own protected resource metadata and reads servers' metadata at registration | FR-AUTHN-1, FR-MCP-2; TC-G2 |
| Authorization server must offer RFC 8414 or OpenID Connect discovery metadata; clients must support both | MUST | IdP choice must satisfy this (ADR-2 spike S2) | FR-AUTHN-1 |
| Client registration: client ID metadata documents (SHOULD be supported), pre-registration, or dynamic client registration (MAY; deprecated, kept for backwards compatibility) | SHOULD / MAY | Registration with platform authorization components is closed by default and enabled per tenant with allowlists, rate limits and owner (both styles) | FR-AUTHN-7; TC-X13 |
| Servers must validate that tokens were issued for them as audience; invalid or expired tokens get 401; access tokens never in the query string; authorization in every request | MUST | Gateway validates audience, expiry and signature on every request; query-string tokens are rejected | FR-AUTHN-1; TC-F2, TC-G2 |
| Servers must not accept or pass through tokens not issued for them; the received client token must not be forwarded upstream; clients send tokens only to servers whose own authorization server issued them | MUST NOT | No token passthrough: audience-bound upstream credentials from the broker (token exchange) | FR-AUTHN-3; CTL-05; TC-G3 |
| Clients must use PKCE with S256 when capable and must refuse to proceed if the authorization server does not advertise support | MUST | Test agents and the dashboard client use PKCE S256; IdP configuration checked | FR-AUTHN-1; IdP spike S2 |
| Clients must record the issuer and check the `iss` parameter before using an authorization code (RFC 9207); servers should send `iss` | MUST (client) / SHOULD (server) | Dashboard and agent client libraries verified for `iss` checking | FR-AUTHN-1; IdP spike S2 |
| Scope handling: servers should include `scope` in `WWW-Authenticate`; clients treat challenge scopes as authoritative; least privilege; step-up re-authorization; insufficient scope should be 403 with `insufficient_scope` | SHOULD / MUST | Policy grants per tool and action class; scope challenges mapped to grants; retries capped | FR-AUTHZ-1..3; CTL-06 |
| Refresh tokens kept confidential; `offline_access` not advertised by servers | MUST / SHOULD NOT | Broker handles refresh tokens; never logged | FR-AUTHN-6; TC-G5 |
| HTTPS for all authorization server endpoints; redirect URIs localhost or HTTPS; exact redirect URI matching; user consent per dynamically registered client for MCP proxy servers using static client IDs | MUST | IdP configuration; consent flow tested | FR-AUTHN-7; TC-X13 |

## 3. Transports

| Specification statement | Strength | Platform response | Requirement / test |
|---|---|---|---|
| Protocol semantics are the same on each transport; messages are UTF-8 JSON-RPC | MUST | Gateway parses and rejects invalid encoding | FR-MCP-1; TC-Z1 |
| stdio: newline-delimited messages with no embedded newlines; server must not write non-MCP content to stdout; stderr may carry logs; shutdown by closing stdin | MUST / SHOULD | Managed wrapper owns stdio, frames and bounds messages, treats stderr as untrusted log text | ADR-5 proposal; FR-MCP-1; TC-Z26 |
| Streamable HTTP: single endpoint accepting POST; responses JSON or event stream; notifications answered with 202 | MUST | Gateway implements both response forms and bounds streaming | FR-MCP-1; TC-Z4 |
| `MCP-Protocol-Version` header on every POST and matching `_meta`; mismatch gets 400 with a header-mismatch error | MUST | Version allowlist enforced; mismatches rejected | FR-MCP-2, FR-MCP-12; TC-P1 |
| `Mcp-Method` required; `Mcp-Name` required for `tools/call`, `resources/read`, `prompts/get` | MUST | Gateway routes on these headers and checks them against the body (header and body must agree) | FR-MCP-2; TC-Z1 |
| Servers may designate tool parameters as headers (`x-mcp-header`); clients must support it | MAY / MUST | Treated as arguments for guards and DLP, including values placed in headers | FR-RT-3; TC-O1 |
| Servers must validate `Origin` on all connections to prevent DNS rebinding; invalid origin gets 403; servers should bind to loopback locally and implement authentication | MUST / SHOULD | Gateway validates origin; local servers bound to loopback; DNS-rebinding case in the SSRF suite | FR-MCP-1; TC-H3 |
| No protocol-level sessions in this revision; servers should return 405 for GET or DELETE on the endpoint and ignore `Mcp-Session-Id` and `Last-Event-ID`; earlier revisions used them | SHOULD | The platform keeps its own sessions bound to the authenticated client; for older revisions the MCP session ID is additionally bound to the client | FR-MCP-3; TC-G4 |
| Server-to-client requests (sampling, elicitation, roots) are carried as `InputRequiredResult` rather than separate requests | MUST | Gateway recognises this form and applies the sampling and elicitation controls to it | FR-MCP-9, FR-MCP-10; TC-Z27, TC-Z28 |
| The older HTTP plus SSE transport is deprecated | SHOULD NOT adopt | Not supported for new servers; legacy servers only through the wrapper with a recorded exception | FR-MCP-2 |

## 4. Client features

| Feature | Specification statement | Strength | Platform response | Requirement / test |
|---|---|---|---|---|
| Sampling | Deprecated as of 2026-07-28 (SEP-2577); new implementations should not adopt it; retained for at least 12 months. Human in the loop with the ability to deny; validate content; rate-limit; set iteration limits for tool loops; respect `maxTokens` | SHOULD NOT / SHOULD / MUST | Denied by default; if enabled for an older revision, budgeted, inspected, approval for high-risk prompts, iteration limits | FR-MCP-9; TC-P2, TC-Z27 |
| Elicitation | Form and URL modes; servers must not request passwords, API keys, tokens or payment credentials in form mode; clients must show which server is asking, show the full URL and obtain consent, must not pre-fetch URLs; servers must bind the elicitation to the user and client; URL mode must not be used for MCP client authorization | MUST / MUST NOT | Denied by default; if enabled, block sensitive form requests; show server and full URL; no pre-fetch; host allowlist | FR-MCP-10; TC-P3, TC-Z28 |
| Roots | Deprecated as of 2026-07-28; informational, not an access-control mechanism; clients must expose only roots with appropriate permissions, validate against path traversal and implement access controls; roots are `file://` URIs | SHOULD NOT / MUST | Limit and audit roots; never rely on them for access control; path-traversal guards | FR-MCP-11; TC-O3 |

## 5. Differences to earlier revisions that matter

| Topic | Earlier revisions | 2026-07-28 | Effect |
|---|---|---|---|
| Sessions | `Mcp-Session-Id` header, GET streams, resumable SSE | No protocol-level sessions | Session binding moves entirely to the platform (FR-MCP-3) |
| Client registration | Dynamic client registration was the common path | Client ID metadata documents preferred; DCR deprecated | Registration abuse covers both (X13) |
| Sampling and roots | Normal features | Deprecated | Default-deny simplified; keep for older servers |
| Auth requirement | Transport guidance varied | Optional; stdio takes environment credentials | Gateway authorization is mandatory in this platform regardless |

Revision-by-revision differences before 2025-06-18 were not reviewed.

## 6. Open items

- Read the pages not yet read (tools, resources, prompts, lifecycle, client ID metadata documents, dynamic client registration, authorization server discovery) and extend the rows.
- Decide the support window: which older revisions the gateway allowlists, and for how long (affects FR-MCP-2 and TC-P1).
- Verify the IdP candidates against Sections 2 rows marked "IdP spike S2" (PKCE S256, `iss` support, discovery formats, resource indicators).
- Re-run this matrix on the next specification revision; the expected `iss` upgrade from SHOULD to MUST in a future revision should be tracked.

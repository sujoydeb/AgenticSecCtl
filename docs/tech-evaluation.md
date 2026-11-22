# Technology Evaluation

| | |
|---|---|
| Version | 0.1 (**provisional: mostly unverified, see Section 1**) |
| Depends on | `Plan/architecture.md` v0.1 (Sections 4, 10, 12 ADRs), `Plan/functional-spec.md` v0.2 |
| Purpose | Decide what to reuse vs build, and feed ADR-1, 2, 5, 6, 7 |
| Rule from the brief | Do not invent product capabilities. Verify current documentation before vendor-specific recommendations. |

## 1. Verification status (read this first)

This evaluation was meant to be grounded in current product documentation. It is not, yet:

- Web research for this document was attempted. Seven of eight searches were blocked by a permission hook in the session and were not retried or routed around. The one that returned results was a secondary-source comparison of licences for Presidio, Prompt Guard 2 and NeMo Guardrails.
- Therefore **almost every vendor, product, licence and protocol statement below comes from general background knowledge and is unverified**. Each is tagged **[VERIFY]**. The only exception is the licence note in Section 3.4, which has secondary-source support and still needs the primary LICENSE file.
- Ratings in the tables are qualitative judgments for shortlisting, not benchmark results. No performance figure here was measured.
- **Do not use this document to make a purchase, licence or architecture-lock decision** until the checklist in Section 8 is completed. Recommendations are limited to what to *spike*, not what to adopt.

### Verification log

| Date | Item | Result | Source |
|---|---|---|---|
| 2026-11-22 | OWASP MCP Top 10 exists (checklist item 5) | **Verified.** An OWASP project named "OWASP MCP Top 10" exists and is described as a living document, with the latest version maintained on GitHub. Secondary articles list entries (e.g., token mismanagement and secret exposure; context injection and over-sharing as MCP10). The full list and identifiers were **not** retrieved; take them from the official project before mapping in the compliance matrix. The document is reported as licensed CC BY-NC-SA 4.0 (non-commercial clause: have legal review before reproducing its text in a commercial product). | [OWASP MCP Top 10 project](https://owasp.org/projects/mcp-top-10), [project page](https://owasp.org/www-project-mcp-top-10/); secondary: [Nordic APIs guide](https://nordicapis.com/guide-to-the-owasp-mcp-top-10/), [Cycode](https://cycode.com/blog/owasp-mcp-top-10/) |
| 2026-11-22 | MCP spec authorization, Cisco scanner, Context Forge, agentgateway, Keycloak DPoP/token exchange (checklist items 1–4) | **Not verified.** Five searches were denied by a permission hook; not retried or bypassed. Rows remain **[VERIFY]**. | — |

## 2. Method and criteria

Each candidate is assessed on the eight criteria from the brief, using a 3-level scale (High/Medium/Low, or the stated fact) and a confidence mark:

| Criterion | Meaning here |
|---|---|
| Security coverage | Which FR/threat IDs it helps with, and what it does not cover |
| Integration | Fit with FastAPI, OPA, OIDC, OpenTelemetry, Kubernetes |
| Deployment complexity | Operational burden for a platform team |
| Licensing | Licence family and any commercial or telemetry caveats |
| Performance overhead | Expected effect on the NFR-1 latency budget (p95 ≤ 25 ms deterministic path) |
| Enterprise readiness | Maturity, governance, support, HA story |
| Limitations | Known gaps relevant to this platform |
| Lock-in | Cost of replacing it later |

Confidence: **V** = supported by a source in Section 9; **U** = unverified background knowledge, to check.

Decision stance (from `Plan/architecture.md` principle 6): integrate mature components for policy, identity, DLP, SBOM, signing, telemetry and secrets. Custom code is limited to MCP-aware control logic. Whether to also reuse an existing MCP gateway is the open question (ADR-1).

## 3. Evaluations by category

### 3.1 MCP security scanners (FR-SCAN-1..5)

| Candidate | Coverage | Integration | Complexity | Licence | Overhead | Readiness | Limitations / lock-in |
|---|---|---|---|---|---|---|---|
| Cisco AI Defense MCP scanner (open-source project) **[VERIFY existence, scope, licence]** | Tool-description analysis (rules plus possibly model-based) — U | CLI/library; Python likely — U | Low | U | Offline scan, off hot path | U | Description-time only; does not cover runtime (threat D, I). Use as rule/corpus source or second opinion |
| Invariant Labs mcp-scan / successor under another vendor **[VERIFY current name, owner, status]** | Tool poisoning, rug-pull style pinning checks — U | CLI — U | Low | U | Off hot path | U | Ownership and roadmap may have changed; do not depend on a hosted API without checking data handling |
| Custom rules engine (our scanner) | Full control of severity taxonomy, reproducible scoring, SoD hooks | Native | Medium (we maintain rules and corpus) | Ours | Off hot path | We own quality | Needs a labelled corpus (spec Section 10); duplicating community rules is wasteful |

**Provisional recommendation:** build the deterministic core (it is small and must be reproducible, FR-SCAN-2); spike one or two external scanners as *advisory secondary signals and as test corpus sources*, behind the pluggable classifier interface (FR-SCAN-3). Hosted scanners require explicit per-tenant opt-in (FR-SCAN-8).

### 3.2 MCP gateways and proxies (ADR-1; FR-RT-*, FR-AUTHN-*)

| Candidate | What to check | Licence | Notes |
|---|---|---|---|
| IBM Context Forge (MCP gateway/registry) **[VERIFY]** | Registry, federation, auth, plugin/hook model, transport support, maturity | U (believed permissive) | Python — would fit the stack if its plugin points can host our pipeline |
| agentgateway **[VERIFY]** | Rust data plane, MCP/A2A support, policy integration | U (believed Apache-2.0, foundation-hosted) | Strong for performance if it exposes the hooks we need; extending in Rust is a skills question |
| Docker MCP Gateway/Toolkit **[VERIFY]** | Container-based server isolation, profile/catalog | U | More developer-desktop oriented; check enterprise multi-tenant story |
| Envoy AI Gateway / Envoy-based **[VERIFY]** | MCP support level, ext_authz / ext_proc hooks to OPA and inspection | U (believed Apache-2.0) | Mature proxy; MCP-aware inspection (tools/list rewrite, hash pin) may need custom filters |
| API gateways with AI plugins (Kong, others) **[VERIFY]** | Any MCP-specific features | U | Often commercial tiers for AI/MCP features |
| Custom FastAPI gateway | Everything in architecture Section 5 | Ours | Fastest path to a correct MVP and pipeline; maintenance and performance risk; may need rewrite in Go/Rust if NFR-1 fails |

**Evaluation tests for the spike** (each candidate must be run, not read about):
1. Can it filter `tools/list` per caller and rewrite names to `namespace__tool`? (FR-INV-2, FR-RT-1)
2. Can a hook deny a call based on an OPA decision and a hash-pin check before forwarding? (stages 4, 6)
3. Can it inspect and modify responses, including streaming? (stage 12)
4. Does it support sender-constrained tokens and token exchange? (FR-AUTHN-2/3)
5. Added p95/p99 latency at 1,000 req/s with a no-op plugin (NFR-1)?
6. Can an audit event with policy hash be emitted for every decision? (FR-AUD-1)
7. Can it run without long-lived upstream secrets in the process? (NFR-9)

**Provisional recommendation:** keep the MVP gateway custom and thin (Phase 1 needs only list filtering and hash-pinned allow/deny), and run the spike above before Phase 2 to decide between continuing custom, building on an Envoy-class proxy with custom filters, or adopting an MCP gateway as the base. This keeps the decision reversible. **[VERIFY all rows first.]**

### 3.3 MCP protocol SDKs

| Candidate | Use | Check |
|---|---|---|
| Official MCP Python SDK **[VERIFY]** | Client/server protocol types, transports; use for scanner importer and fixtures; gateway proxying support level is unknown | Current protocol revision supported, Streamable HTTP support, whether it can act as a transparent proxy, release cadence, licence |
| Other-language official SDKs (TypeScript, Go, Rust, etc.) **[VERIFY]** | Possible gateway implementation language if Python fails NFR-1 | Feature parity, maturity |

The MCP specification revision and its authorization section must be pinned and re-reviewed on every revision (threat model Section 9, ADR tracking). **[VERIFY current revision and auth requirements: OAuth 2.1 profile, resource indicators (RFC 8707), protected resource metadata (RFC 9728), dynamic client registration status.]**

### 3.4 Policy engines (ADR-6; FR-AUTHZ-1, FR-POL-*)

| Candidate | Coverage | Integration | Complexity | Licence | Overhead | Readiness | Limitations / lock-in |
|---|---|---|---|---|---|---|---|
| OPA / Rego | General decision engine; bundles, decision logs, `opa test` | HTTP/sidecar/library; mature ecosystem | Medium (Rego learning curve) | Apache-2.0, CNCF — U | Low per decision when local — U | High — U | Rego skills needed; large data in policy needs care (bundle size, latency) |
| Cedar **[VERIFY]** | Entity-based authz with formal analysis tooling | Libraries mainly Rust; Python bindings maturity unknown | Medium | Apache-2.0 — U | Low — U | Medium — U | Smaller ecosystem; decision logging/bundles are your job |
| OpenFGA / SpiceDB (relationship stores) **[VERIFY]** | Large agent–server–tool relationship graphs | Service | Medium-High | U | Network hop | U | Add only if relationships outgrow OPA data |

**Provisional recommendation:** OPA/Rego for MVP (matches the spec's FR-POL-1 and `opa test` in CI); revisit Cedar only if formal analysis becomes a requirement. Measure decision latency with realistic policy data before fixing the caching design.

### 3.5 Identity providers (ADR-2; FR-AUTHN-*, FR-ID-*)

The critical capability questions are the same for every IdP: sender-constrained tokens (DPoP or mTLS-bound), token exchange (RFC 8693), resource indicators, client registration controls, revocation, short token lifetimes, SPIFFE/workload identity integration.

| Candidate | Role | Check |
|---|---|---|
| Keycloak **[VERIFY]** | Development and possibly production (self-hosted) | Current support level of DPoP, token exchange (standard vs preview/legacy), mTLS binding; HA operations; licence (believed Apache-2.0) |
| Okta / Auth0 **[VERIFY]** | Commercial SaaS options | DPoP and token exchange availability per plan; MCP-specific authorization features |
| Microsoft Entra ID **[VERIFY]** | Common enterprise IdP | Support for DPoP, on-behalf-of flow vs RFC 8693, resource indicators; the Microsoft Learn docs are the authoritative source |
| SPIFFE/SPIRE **[VERIFY]** | Workload identity for agents/services | Fit with OAuth client model; operational burden |

**Provisional recommendation:** use Keycloak in development as planned; the production IdP is the customer's. Treat sender-constrained tokens as "required if IdP supports it, otherwise documented fallback" exactly as in FR-AUTHN-2, and record the actual mode in test results (TC-G1). Capability gaps found here should be fed into the open decision in spec Section 12.

### 3.6 DLP and PII detection (FR-RT-6)

| Candidate | Coverage | Licence | Notes |
|---|---|---|---|
| Microsoft Presidio | PII entity recognition and anonymization; pattern + NLP recognizers; custom recognizers | MIT per a secondary source ([Section 9](#9-sources)); confirm against the repository LICENSE | Python-native; NLP model choice affects latency and recall; free-text recall is limited, structured identifiers are strong **[VERIFY performance on our payload sizes]** |
| gitleaks / trufflehog **[VERIFY]** | Secret and key patterns | U (believed MIT / AGPL respectively — check) | Library or CLI; entropy rules give false positives |
| Cloud DLP (Macie, Google Cloud DLP, Purview) **[VERIFY]** | Data-at-rest and API-based inspection | Commercial | Sends content to a cloud service: conflicts with data-minimisation and latency goals for the inline path; better for stored evidence scans |
| Custom checksum validators (Luhn, IBAN) | Deterministic financial identifiers | Ours | Small; wrap around Presidio results |

**Provisional recommendation:** Presidio-style engine behind our `inspect()` interface for Tier 1, plus a secret scanner library and our own checksum validators; cloud DLP only for offline scans. Measure latency on typical response sizes before deciding which recognizers run inline.

### 3.7 Prompt-injection and content classifiers (advisory only; FR-RT-4/11, FR-SCAN-3)

| Candidate | Notes | Licence caveat |
|---|---|---|
| Llama Prompt Guard 2 / Llama Guard family **[VERIFY]** | Small classifiers usable on our infrastructure | A secondary source says Meta's Llama community licence applies, which is not a permissive open-source licence; read the model card terms before bundling or redistributing |
| NVIDIA NeMo Guardrails **[VERIFY]** | Guardrail framework (rails, integrations) | Apache-2.0 per a secondary source; its documentation notes startup telemetry to NVIDIA, which matters for air-gapped/regulated deployments |
| Commercial detection services (cloud-provider guardrails, specialist vendors) **[VERIFY]** | Hosted APIs | Data leaves the boundary (GDPR/bank policy review); latency; vendor lock-in |

**Constraints that apply to all of them (non-negotiable by design):** outputs are signals, never the sole control (FR-RT-11, principle 2); false-positive and false-negative rates must be measured on our own labelled corpus in shadow mode (spec Section 10); self-hosted option required (FR-SCAN-8). Published benchmark claims from vendors should not be used as acceptance evidence.

### 3.8 Supply chain, container and vulnerability tooling (FR-SCAN-5, FR-SUP-*, NFR-9)

| Need | Candidates **[VERIFY each]** | Notes |
|---|---|---|
| SBOM | Syft, CycloneDX/SPDX generators | Formats: CycloneDX and SPDX are open standards |
| Vulnerability scanning | Grype, Trivy, OSV-Scanner | Overlapping coverage; run two sources if false-negative risk matters; check DB update behaviour in air-gapped setups |
| Signing/provenance | Sigstore cosign, SLSA provenance, in-toto | Keyless signing needs reachable public infrastructure unless self-hosted; decide per deployment |
| SAST | Semgrep (OSS), Bandit | Check licence of rule sets separately from the engine |
| Secrets in CI | gitleaks | — |
| Repo posture | OpenSSF Scorecard | Useful for third-party server intake (FR-SUP-3) |
| Admission control | Kyverno, OPA Gatekeeper | Pick one; Kyverno policies are YAML, Gatekeeper reuses Rego (skills reuse with OPA) |
| Runtime detection | Falco **[VERIFY]** | Needs kernel/eBPF support in target clusters; tune for noise |
| Sandboxed runtimes | gVisor, Kata Containers **[VERIFY availability per cloud and compatibility with target workloads]** | Performance and syscall-compatibility costs |

**Provisional recommendation:** adopt standard open tooling in CI from day one (SBOM, two scanners spike, secret scanning, signing), because these have no custom-code alternative. Decide Kyverno vs Gatekeeper after policy-skills review.

### 3.9 Data and eventing infrastructure

| Component | Choice for MVP | Notes **[VERIFY]** |
|---|---|---|
| Database | PostgreSQL | Row-level security, triggers for immutability (FR-DRIFT-1), insert-only roles for audit; PostgreSQL licence is permissive |
| Cache/session store (Phase 2) | Redis or a compatible fork (e.g., Valkey) | Redis licensing changed in recent years; confirm the current licence and compatible alternatives before standardising |
| Event streaming (Phase 2) | Outbox → Kafka (or managed equivalent) | Only if volume or SIEM integration justifies; start with the outbox table and OTel exporters |
| Telemetry | OpenTelemetry (SDKs, Collector) | Check stability of GenAI semantic conventions before depending on them; use stable HTTP/DB conventions for platform telemetry |
| Secrets/keys | Vault, OpenBao, cloud KMS/secrets managers | HashiCorp changed Vault's licence in 2023 and a community fork exists; confirm current terms and customer standard |
| Audit anchoring | Object-lock storage (S3-compatible with object lock), external timestamping | ADR-7; confirm object-lock support in each target cloud/storage |

### 3.10 SIEM / SOAR and cloud-native services

| Area | Approach |
|---|---|
| SIEM | Export via OpenTelemetry/CloudEvents; do not build analytics UI beyond the fleet dashboard. Splunk, Microsoft Sentinel, Google Chronicle, Elastic are candidates; the customer's SIEM decides (spec Section 12). Check each ingest format and per-GB cost **[VERIFY]**. |
| SOAR | Webhook adapters from incident manager (FR-IR, FR-ADM-3); playbook automation (Phase 4) should call existing SOAR where one exists rather than rebuilding it **[VERIFY product options]**. |
| Cloud-native AI guardrails and posture tools | Treat as optional signal sources per cloud; none is assumed to cover MCP-specific threats **[VERIFY per cloud]**. |
| Cloud egress/metadata hardening | IMDSv2 enforcement and pod-level metadata blocking per cloud (threat H) **[VERIFY per cloud]**. |

## 4. Summary decision table

| Area | Provisional direction | Confidence | Build vs reuse | Linked decision |
|---|---|---|---|---|
| Scanner rules and scoring | Own deterministic core; external scanners as advisory/corpus | Medium | Build core, reuse signals | FR-SCAN |
| Gateway | Custom thin MVP; spike MCP gateways and Envoy before Phase 2 | Low-Medium | Decide after spike | ADR-1 |
| Policy | OPA/Rego | Medium-High | Reuse | ADR-6 |
| Identity | Keycloak (dev); customer IdP (prod); verify DPoP/token exchange | Low until verified | Reuse | ADR-2 |
| DLP | Presidio-style + secret scanner + own validators | Medium | Reuse + thin custom | FR-RT-6 |
| Injection classifier | Self-hostable small classifier, advisory | Low until measured | Reuse | FR-RT-11 |
| Supply chain tooling | Syft/Grype/Trivy, cosign, SLSA | Medium | Reuse | FR-SCAN-5 |
| Datastores/eventing | Postgres; Redis-compatible and Kafka in Phase 2 | Medium | Reuse | — |
| Telemetry | OpenTelemetry | Medium-High | Reuse | FR-OBS |
| Secrets | Customer standard (Vault/OpenBao/cloud) | Low until verified | Reuse | NFR-9 |
| Anchoring | Object-lock storage | Medium | Reuse | ADR-7 |

## 5. Risks of this evaluation
- **Staleness:** MCP and agent-security tooling changes monthly. Every row needs a "last verified" date once checked.
- **Marketing claims:** vendor detection-rate claims must be re-measured on our corpus.
- **Licence shifts:** several relevant projects have changed licences in recent years; legal must review before bundling anything.
- **Data egress:** any hosted detector sends tool content to a third party; this conflicts with GDPR minimisation and bank data policies unless contracted and scoped.
- **Over-integration:** each integrated tool adds an operational and supply-chain surface (NFR-9). Prefer fewer, well-supported components.

## 6. Spike plan (before Phase 2 gate)

| Spike | Goal | Time-box | Exit evidence |
|---|---|---|---|
| S1 Gateway options | Run the seven tests in Section 3.2 against custom FastAPI, one MCP gateway, one Envoy-based setup | 2 weeks | Table of results and latency numbers; ADR-1 decision |
| S2 IdP capabilities | Test DPoP/mTLS binding, token exchange, resource indicators on Keycloak and the customer's candidate IdP | 1 week | Capability matrix; ADR-2; FR-AUTHN-2 mode statement |
| S3 Policy latency | OPA decision p95 with realistic data sizes, bundle update behaviour, stale-bundle handling | 1 week | Numbers against NFR-1; caching design |
| S4 Detectors | Presidio and one classifier on a labelled corpus in shadow mode | 2 weeks | Precision/recall, latency, licence note |
| S5 Scanner baselines | Run external MCP scanners on the poisoned/benign corpus; compare to our rules | 1 week | Detection overlap, false positives |
| S6 Supply chain pipeline | SBOM + scanners + signing + admission in a sample pipeline | 1 week | Working gate; TC-L2, TC-L3 runnable |

## 7. Alternatives considered at the architecture level
- **Buy rather than build the whole platform:** not assessed. Product landscape unverified; revisit after S1/S5 by checking whether any single product meets the spec's must-have requirements (separation of duties, hash-pinned approval, audit hash chain, bank-grade evidence). **[VERIFY market]**
- **Agent-framework-embedded controls instead of a gateway:** rejected as primary control because it cannot cover multiple frameworks and models (spec goals), but useful as an additional layer.

## 8. Verification checklist (to complete before approving this document)

For every **[VERIFY]** row: capture URL, version/date checked, licence file, and a one-line fact. Priority order:
1. MCP specification: current revision, authorization section, transports, sampling/elicitation/roots wording.
2. Candidate MCP gateways: licence, MCP support, extension points, release activity.
3. Keycloak and customer IdP: DPoP, token exchange, resource indicators.
4. Existing MCP scanners: existence, licence, rules, data handling.
5. OWASP MCP guidance: ~~whether a Top 10 exists~~ (verified, see log); still needed: the full list, identifiers and current version from the official project, for the compliance matrix.
6. Presidio, Prompt Guard 2, NeMo Guardrails: primary LICENSE/model-card terms.
7. Redis/Valkey and Vault/OpenBao current licences.
8. Cloud specifics: egress controls, metadata hardening, object-lock, sandboxed runtimes per target cloud.

Authoritative source types to use: project repositories (LICENSE, README, release notes), the MCP specification site, vendor product documentation, and, for Microsoft/Azure, Microsoft Learn.

## 9. Sources

Only the following sources were consulted, and they are secondary:
- NVIDIA NeMo Guardrails documentation: [overview](https://docs.nvidia.com/nemo/guardrails/about-nemo-guardrails-library/overview), [PII detection](https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog/pii-detection.md), [runtime security FAQ](https://docs.nvidia.com/nemo/guardrails/latest/resources/runtime-security-faq.md) (telemetry note and feature descriptions)
- [AI guardrails comparison, AIMultiple](https://aimultiple.com/ai-guardrails) and [Best LLM guardrails tools, DevToolLab](https://devtoollab.com/blog/best-llm-guardrails-tools) (licence statements for Presidio, NeMo Guardrails, Prompt Guard 2; secondary, conflicting on Prompt Guard 2 details)

Everything else in this document is unverified background knowledge.

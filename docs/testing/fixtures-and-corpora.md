# Test Fixtures and Detector Corpora

| | |
|---|---|
| Version | 0.1 (specification; closes gap G5 and the corpus part of E6 in `docs/reviewgap.md`) |
| Depends on | `docs/testing/cases.md` v0.5 (Section 1 fixtures), `Plan/functional-spec.md` v0.8 (Section 10 detector budgets, FR-SCAN-10), `docs/deployment-architecture.md` v0.4 (Section 13 Compose topology), `docs/roadmap.md` v0.5 (Phase 1 harness) |
| Status | Specification plus a **seed corpus** in `tests/fixtures/corpus/` (42 tool descriptions, 28 responses). The fixture servers and the harness are not implemented. The seed corpus is too small to measure precision or recall. |

## 1. Fixture servers

All fixtures run only on the internal, no-route-out network (deployment architecture Section 13). Every fixture records every request it receives (time, source, method, path, body digest) so tests can assert both what was reached and what was not. Each mode is selected per test run by an environment variable or control endpoint and is deterministic.

### 1.1 FX-BEN (benign MCP server, `tests/fixtures/benign_mcp`)
| Tool | Action class | Behaviour |
|---|---|---|
| `docs_search` | read | Returns canned documents, some containing FX-CANARY strings |
| `note_write` | write | Stores a note in memory; returns an identifier |
| `file_delete` | delete | Deletes a test file inside a temporary root only |
| `shell_exec` | execute | Runs a fixed allowlisted command set inside the sandbox profile used for tests |

### 1.2 FX-EVIL (hostile MCP server, `tests/fixtures/evil_mcp`)
Modes (one per case; names match the cases in `docs/testing/cases.md`):

| Mode | Behaviour | Cases |
|---|---|---|
| `unicode`, `override`, `url`, `crosstool`, `encoded` | Poisoned tool descriptions of each style | TC-A1..A5 |
| `mutate-after-list`, description or schema change, annotation flip, `list_changed` | Definition changes at controlled times | TC-B1..B4, TC-Z3 |
| `shadow` | Duplicate tool name | TC-C1 |
| `html-inject`, `json-inject`, `md-exfil`, `error-inject`, `multimodal` | Injected responses and errors, non-text content | TC-D1..D3, TC-X10, TC-X11 |
| `redirect`, DNS answers alternating, alternate IP encodings | SSRF triggers | TC-H1..H4 |
| `callhome` | Outbound connection attempts | TC-I4 |
| `sampling`, `sampling-loop`, `elicit`, `notify-flood`, `huge`, `slowloris` | Protocol and resource abuse | TC-P2..P4, TC-Z4, TC-Z27, TC-Z28 |
| `registration-abuse` | Client metadata documents on an attacker host | TC-X13 |
| `agent-card` | Forged agent card | TC-X9 |

### 1.3 Supporting fixtures
| Fixture | Content |
|---|---|
| FX-IDP | Keycloak realm with agents `agent-ro`, `agent-rw`, `agent-adm`, requester and approver users, tenants T1 and T2, sender-constrained token mode switchable |
| FX-OPA | OPA with the test bundle; controllable to serve stale or unsigned bundles or stop |
| FX-SIEM | Sink capturing structured logs and audit exports for assertions |
| FX-CANARY | Fake secrets and PII with recognisable markers (valid-format fake API key, Luhn-valid test card number, fake national ID pattern) |
| FX-META, FX-INT | Recording fake metadata endpoint and fake internal API |
| FX-EXT-CLASSIFIER | Recording stand-in for an external classifier service (TC-Z13) |

## 2. Harness requirements (Phase 1 deliverable)

1. One command starts the Compose `e2e` profile and runs the MVP set (19 cases); another runs the full suite.
2. Each test declares its fixture mode, expected audit events and assertions on fixture request logs.
3. Results are written as machine-readable reports with: build, rule-set version, policy bundle hash, case ID, outcome, evidence references.
4. Tests are independent: they create their own tenants and data and clean up.
5. Clock control for expiry and TTL tests; randomised timing for race tests (TC-Z3).
6. Hostile fixtures never run outside the isolated network; CI refuses to start them elsewhere.

## 3. Corpora for detector quality

### 3.1 Why
Detector budgets (specification Section 10: scanner rules at least 95% recall and 90% precision on a labelled corpus; response injection false-block rate at most 0.5% in shadow mode; DLP precision targets) cannot be accepted without labelled data that is versioned and independent of the rules.

### 3.2 Format
JSON Lines, one object per line, UTF-8 with non-ASCII characters escaped.

| File | Fields |
|---|---|
| `tool_descriptions.jsonl` | `id` (TD-nnn), `label` (`benign` or `poisoned`), `category`, `expected_min_severity` (`none`, `medium`, `high`, `critical`), `text` |
| `tool_responses.jsonl` | `id` (TR-nnn), `label` (`benign` or `injected`), `category`, `text` |
| DLP corpus (to be added) | `id`, `entity_type`, `label`, `text`, `expected_action` |

Categories for descriptions: `override`, `credential_request`, `exfil_url`, `cross_tool`, `hidden_unicode`, `hidden_bidi`, `encoded`, `schema_anomaly`, `concealment`, `homoglyph`. For responses: `html_comment`, `json_field`, `markdown_image`, `tool_request`, `hidden_element`, `error_message`, `role_confusion`, `multilingual`, `split`, `encoded`.

### 3.3 Labelling rules
- A sample is `poisoned` or `injected` only if a reviewer can state which instruction it carries and what harm it aims at; otherwise `benign`.
- Benign samples must include hard negatives: legitimate text with words such as ignore, delete, password, URLs to documentation, imperative phrasing.
- Two reviewers label each sample independently; disagreements are resolved by a third and recorded; the agreement rate is reported.
- Samples are inert: reserved domains and private test addresses only, no working exploit code.
- Real customer data never enters the corpus.

### 3.4 Splits and versioning
Development set (rules may be tuned on it) and held-out test set (never used for tuning); the held-out set changes only by adding samples, with a new version tag. Every scan and detector run records the corpus version and the rule-set or model version. Evasion samples found in the field are added with a new ID and are included in the regression set run on every update (FR-SCAN-10).

### 3.5 Metrics
Per category and overall: true positives, false positives, false negatives, precision, recall, and for responses the false-block rate on benign traffic in shadow mode. Report confidence intervals; a result on fewer than 100 samples per class is reported as indicative only.

### 3.6 Size targets (proposal)
Seed (today): 42 descriptions, 28 responses (includes hard negatives and categories for error-message, resource-template, image-alt-text and agent-card injection). Phase 1: at least 200 descriptions (at least 100 benign enterprise-style) and 100 responses. Phase 2: at least 500 descriptions, 300 responses and a DLP corpus per entity type before detector budgets are enforced. These counts are proposals.

## 4. Ownership and process

The test lead owns the corpus and fixtures; the security engineer proposes new samples; an independent reviewer approves the held-out set. Changes go through the normal review; the corpus is checked by `scripts/check_docs.py` for well-formed JSON Lines, unique IDs and valid labels.

## 5. Open items

- Build the fixtures and harness; decide the implementation language for fixtures.
- Grow the corpus to the proposed sizes; find an external, licensed source of benign enterprise tool descriptions (licence to be checked).
- Define the DLP corpus and expected actions per tenant policy.
- Decide who the independent reviewers are (governance document).

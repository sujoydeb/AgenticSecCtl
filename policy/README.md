# policy

Rego policies and their tests (`docs/authn-authz-design.md` Sections 4 to 7).

**Status: Phase 1 policy (WP-1.8), tested but not yet used by a gateway.** `rego/authz.rego` is the product policy for the Phase 1 decision contract (`docs/authn-authz-design.md` Section 5). Query `data.agentic.authz.decision`: it always returns `{allow, reasons, obligations, policy_hash}`. A decision is allowed only when no denial reason applies; every denial has at least one stable reason code; every decision carries the bundle hash (FR-POL-2).

Fail-closed behaviour the tests pin down: a missing or mistyped input field, a missing, malformed or stale bundle (limit `max_age_seconds`, boundary second is stale, a bundle dated more than 60 s ahead is invalid), an unparsable grant expiry, a just-in-time grant without expiry, a resource with a `..` segment, and an unknown tenant, agent or server all deny. The spike found and fixed an expiry comparison that treated every expiring grant as expired; the product policy also closes the opposite hole (an unparsable expiry used to count as not expired).

Not in this policy: the fail-open allowlist of FR-AUTHZ-8 (its second sentence; default deny stays, and it is a gateway behaviour decided in WP-1.9), management-API actions (`agentic.mgmt`; roles are checked in code, WP-1.10), signing of bundles (FR-POL-3, Phase 3), shadow mode (FR-POL-4, Phase 3), limits and taint (Phase 2; only the input field `session.taint` is read).

Build the bundle (standard library only, reproducible, hash of the `.rego` files):

```
python3 -I policy/build_bundle.py --out dist --registry registry.json --grants grants.json [--max-age 300]
```

`tests/unit/test_policy_bundle.py` builds it, checks determinism and the hash, and evaluates the built bundle with OPA in Docker.

Run (OPA 1.22.4 in the official container; any OPA 1.x should work):

```
docker run --rm -v "$PWD/policy":/w -w /w openpolicyagent/opa:latest test rego tests
docker run --rm -v "$PWD/policy":/w -w /w openpolicyagent/opa:latest check --strict rego tests
docker run --rm -v "$PWD/policy":/w -w /w openpolicyagent/opa:latest fmt --list rego tests
```

CI runs the same three commands in the `spikes` job of `.github/workflows/docs-check.yml`, with the OPA image pinned by digest (first GitHub run passed, 2026-11-22). Last run: see `docs/testing/results/` (WP-1.8). The tests are a decision table of about 40 named cases (TC-F1, TC-E1, TC-C3, TC-B1, TC-E3, TC-D4, TC-D5), one case per required input field removed and per wrong type, and the bundle cases (hash on every decision, stale, future-dated, malformed). Cases that need the gateway (TC-Z5 end to end, TC-M2) are not covered here.

Data shape: `data.registry.agent_server_allow[tenant][agent][server] = true` and `data.grants[tenant][agent] = [grant, ...]`.

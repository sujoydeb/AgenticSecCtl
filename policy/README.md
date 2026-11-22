# policy

Rego policies and their tests (`docs/authn-authz-design.md` Sections 4 to 7).

**Status: spike S3 draft, not the product policy.** `rego/authz.rego` is the sketch from the design document, made to run: the `resource_matches` helper is written, the expiry comparison is fixed (the sketch compared an integer with a string, which made every expiring grant look expired), and the agent-to-server data is a keyed lookup instead of a list scan. WP-1.8 builds the real policy from here.

Run (OPA 1.22.4 in the official container; any OPA 1.x should work):

```
docker run --rm -v "$PWD/policy":/w -w /w openpolicyagent/opa:latest test rego tests
docker run --rm -v "$PWD/policy":/w -w /w openpolicyagent/opa:latest check --strict rego tests
docker run --rm -v "$PWD/policy":/w -w /w openpolicyagent/opa:latest fmt --list rego tests
```

CI runs the same three commands in the `spikes` job of `.github/workflows/docs-check.yml`, with the OPA image pinned by digest (first GitHub run passed, 2026-11-22). Last run on 2026-11-22 (locally): 15 of 15 tests pass, `check --strict` and `fmt --list` report nothing. The tests mirror TC-F1, TC-E1, TC-C3, TC-B1, TC-E3, TC-D4, TC-D5 and the fail-closed cases (missing field, empty input, unknown tenant). Cases that need the gateway (TC-Z5, TC-M2) are not covered here.

Data shape: `data.registry.agent_server_allow[tenant][agent][server] = true` and `data.grants[tenant][agent] = [grant, ...]`.

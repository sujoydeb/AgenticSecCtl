# Test results

Saved output of the package gates, one file per run: `<date>-<work package>.md`, written by `scripts/run_gate.py`. Each file records the commit, whether the working tree had uncommitted changes, the machine, every command and its full output.

These are evidence from single runs on a developer machine. They show what passed at that moment; they do not certify the platform, and the test cases in `docs/testing/cases.md` remain specifications until the end-to-end harness (WP-1.12) runs them. A later run of the same package overwrites the file for the same date.

| Package | Result file | Notes |
|---|---|---|
| WP-1.4 audit chain, verifier, replay | `2026-11-23-wp-1.4.md` | Unit tests only; the database-backed writer is WP-1.6. Detection of a full-chain rewrite needs an anchor (Phase 2, TC-Z22). |
| WP-1.5 schema, runner, tenant helper | `2026-11-23-wp-1.5.md` | PostgreSQL 17.12 in Docker: migrations 0001 and 0002 up, down, up and the 82 schema checks; the migration runner (checksums, atomic failure, concurrent runners); the tenant-per-transaction helper over a pool of one connection (with the reset disabled, four leak tests fail). Frozen only after ADR-4 is decided. |
| WP-1.8 policies | `2026-11-23-wp-1.8.md`, `2026-11-23-wp-1.8-mutations.md` | OPA tests, strict check, format check, bundle build and evaluation by OPA. 16 deliberate weakenings of the policy, all caught. Not yet exercised behind a gateway (WP-1.9). |
| WP-1.10 identity | `2026-11-23-wp-1.10.md`, `2026-11-23-wp-1.10-mutations.md` | Token validation, key-set handling, principals, roles, realm file shape. 13 deliberate weakenings, all caught. **Keycloak itself was not started**, so "the harness logs in as every role" (the package's done-when) is not shown; that is WP-1.12. |

The `*-mutations.md` files come from `scripts/run_mutations.py`: each line weakens the code in one named way, runs the package tests and expects a failure. A surviving mutation means a test gap; one survivor was found and closed during WP-1.10 (the principal kind check had no test of its own).
| WP-1.6 registry API | `2026-11-23-wp-1.6.md`, `2026-11-23-wp-1.6-mutations.md` | Registry service, approvals, separation of duties, Critical-finding overrides, database-backed audit chain with tamper detection, and the HTTP API driven with real signed tokens against PostgreSQL. 17 deliberate weakenings, all caught. Covers the registry subset only: suspension, grants, incidents, evidence packs, the scanner endpoints and the gateway event endpoint are not built. The api tests are not in CI yet (full dependency lock with hashes first). |

# Holistic test and findings, 2026-11-23

Whole-system check of everything built through WP-1.8 and WP-1.10 before starting WP-1.9. Commit under test: `54d5481` (branch `phase1-implementation`, identical on GitHub). One developer machine; the CI job that will run the same steps has not run on GitHub yet.

## What was run

| Check | How | Result |
|---|---|---|
| The committed state is self-contained | Fresh `git clone` of the branch into an empty directory; nothing from the working tree | 189 tracked files, all checks below ran from it |
| Dependencies are fully locked | Virtual environments built from `--require-hashes` lock files only | Pass on macOS Python 3.15, macOS 3.12, Linux 3.12; `pip check` clean |
| Supported Python floor | Whole suite on Python 3.12 (development was on 3.15) | Pass |
| Linux | Python 3.12 container (tests that need Docker skip themselves there) | Pass; 117 tests skipped by design |
| Lint | `ruff check .` | Clean (after fixes below) |
| Strict types | `mypy` strict on 36 production files | Clean (after fixes below) |
| Unit, service, integration tests | `scripts/check_all.sh`: 33 repo, 168 common, 92 api, 69 scanner, 25 integration | Pass |
| Whole-story walkthrough | `tests/e2e/test_phase1_walkthrough.py`: API, scanner, PostgreSQL, audit chain, real policy engine, two tenants | Pass; transcript in `2026-11-23-holistic.md` |
| Database | 85 schema checks, migrations 0001 to 0003 up, down, up | Pass |
| Policy | `opa test`, `check --strict`, `fmt` | Pass |
| Documents | `check_docs.py`, YAML and OpenAPI validation, lock files current | Pass |
| Production-code sweep | Search for eval, exec, pickle, shell, unverified TLS, weak hashes, non-cryptographic randomness | None found |

Clean-clone output (`check_all.sh` per environment):

```text
##### Python 3.15 macOS
code checks: ok
All checks passed!
Success: no issues found in 36 source files
Ran 33 tests in 5.366s
OK
Ran 168 tests in 14.447s
OK
Ran 92 tests in 45.094s
OK
Ran 69 tests in 7.148s
OK (expected failures=4)
Ran 25 tests in 34.822s
OK
Ran 1 test in 17.874s
OK
all checks passed
##### Python 3.12 macOS
code checks: ok
All checks passed!
Success: no issues found in 36 source files
Ran 33 tests in 7.329s
OK
Ran 168 tests in 14.537s
OK
Ran 92 tests in 45.425s
OK
Ran 69 tests in 7.475s
OK (expected failures=4)
Ran 25 tests in 33.302s
OK
Ran 1 test in 17.374s
OK
all checks passed
##### Python 3.12 Linux container (no Docker inside: Docker-based tests skip)

code checks: ok
All checks passed!
Success: no issues found in 36 source files
Ran 33 tests in 2.709s
OK (skipped=4)
Ran 168 tests in 15.233s
OK
Ran 92 tests in 0.011s
OK (skipped=87)
Ran 69 tests in 6.855s
OK (expected failures=4)
Ran 25 tests in 0.001s
OK (skipped=25)
Ran 1 test in 0.000s
OK (skipped=1)
all checks passed
```

## Defects found by the holistic pass, and fixed

1. **Lint and type checks had never run.** They were configured in WP-1.1 and never executed. First run: 756 lint issues (mostly style) and 93 type errors. Both now pass and are gates in `check_all.sh` and in the CI job, from a hash-locked `requirements-dev.lock`.
2. **A safety check that disappears under `python -O`.** The guard in front of an SQL statement that interpolates a table name was an `assert`. Nothing untrusted reached it, but a guard must not depend on an interpreter flag. Now a real check with a test.
3. **Seven more `assert` statements** doing type narrowing after `INSERT ... RETURNING`: replaced by explicit errors, as the project's own rule says.
4. **Connections typed as tuple rows although they return dictionaries** (38 type errors, hiding real mistakes): one alias, `Conn`.
5. **The role store was typed as the in-memory class**; now a protocol both implementations satisfy.
6. **`None` handling:** the token not-before check, the audit verifier's sequence number, and the SSRF exception entry's expiry were typed as possibly `None` where the code assumed otherwise; made explicit.
7. A closure over a loop variable in decision replay, an unlogged `except: pass` around the advisory classifier (now logs at debug level), and a script crash on a package with an empty licence field.

## Gaps found, NOT fixed (these need a decision)

| # | Gap | Evidence | Consequence |
|---|---|---|---|
| G1 | **Nothing can approve an MCP server.** The policy requires `server.status == "approved"`; no API sets it; the specification's approval subjects are tool version, agent, grant and call only | Walkthrough step 5 had to run `UPDATE mcp_servers SET status = 'approved'` | No call can be allowed through the product's own interfaces |
| G2 | **No way to create the agent-to-server allowlist** (FR-AUTHZ-2) | Same step: direct `INSERT INTO agent_server_allow` | Same |
| G3 | **No way to create a static permission grant** (FR-AUTHZ-3). The only grant endpoint in the specification is the just-in-time `POST /grants`, which is not built either | Same step: direct `INSERT INTO permissions` | AC-3 ("grant, then allow") cannot be met end to end |
| G4 | **Nothing turns registry rows into policy data and input.** The walkthrough does it in test code | Step 6 | This is the core of the gateway's registry client (WP-1.9) and of `GET /internal/registry/view` |
| G5 | **No process entry points.** The API and the worker have no `main`, no wiring of the redacting JSON log formatter, no token acquisition for the worker | `services/api/README.md`, `services/scanner/README.md` | They run only inside tests; log redaction is not active in a real process |
| G6 | **A refused approval because of Critical findings is not audited** (it returns 409 without an event) | Walkthrough step 3 | A blocked high-risk approval attempt leaves no trace |
| G7 | **The Keycloak realm has never been started.** Its shape is tested, not its behaviour | | "The harness logs in as every role" is not shown |
| G8 | **The CI jobs have not run on GitHub** | | The workflow is untested as a workflow |

## What the results do not show

- One developer machine. Not a performance, load or soak test. No penetration test.
- The scanner's measured quality is in `2026-11-23-wp-1.7-scanner-baseline.md`: strong on text written the way the rules expect, 0 of 16 against deliberate evasion.
- The walkthrough checks that components agree with each other on the cases it builds; it is not a proof that no other combination misbehaves.

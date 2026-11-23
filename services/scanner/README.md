# agenticsecctl-scanner

Import, scan and report (control plane). Phase 1, WP-1.7. Standard library only; talks to the API, never to the database.

| Module | What it does |
|---|---|
| `normalise.py` | Makes evasions visible: hidden characters (offsets), Unicode tag text decoded, right-to-left override text read in reverse, look-alike letters folded, base64/hex/percent blobs decoded (3 layers) |
| `rules.py` | The deterministic rules (rule ID, severity, confidence), the reproducible score `min(100, sum(weight x confidence))`, and the rule-set version and hash |
| `scan.py` | `scan_tool`: scan one definition, every string at its path; pure, no network |
| `classifier.py` | Advisory classifier interface and the stub. It may add a medium signal; it can never lower a finding or approve anything |
| `importer.py` | Hardened `tools/list` import: wall-clock deadline, size, depth, node, string, tool and page limits, no redirects, duplicate keys and NaN refused |
| `worker.py` | Claim a job from the API, import, scan, post the result or a stable failure reason |

## What the scanner is, and is not

A set of pattern rules over untrusted text. On text written the way the rules expect it finds almost everything; against deliberate evasion it finds almost nothing. Measured on 2026-11-23 (`docs/testing/results/2026-11-23-wp-1.7-scanner-baseline.md`):

| Set | Samples | Recall | False positives |
|---|---|---|---|
| Development (rules written against it, so optimistic) | 24 poisoned, 18 benign | 100% | 0 |
| Held-out (committed before any rule; same author as the rules) | 16 poisoned, 14 benign | 100% | 0 |
| Evasion (written to get around the rules) | 16 poisoned | **0%** | n/a |

None of these sets is large enough to prove a 95% recall or 90% precision target (the intervals are wide), and the targets are not met against adaptive attackers. **Do not read a clean scan as safety.** Known misses, also pinned as expected failures in `tests/test_scan.py`: paraphrase without trigger words, other languages, leetspeak, letters split by punctuation, text split across fields, layered encoding deeper than three levels, rot13 and base32, obfuscated URLs and decimal IPs, an instruction placed in the middle of more than 50,000 characters. This is why a scan result only *adds* evidence: a Critical finding blocks approval (two-approver override), and approval, hash pinning, the gateway and the runtime controls carry the rest. A compromised worker could post fewer findings; the tool would still need a human approval.

## Isolation

The worker has no database credential and no secret. `tests/integration/test_scanner_isolation.py` runs it in a container on a network that contains only the API, as an unprivileged user on a read-only file system with no capabilities, and checks that a direct database connection (by name and by address), the metadata address, a private address and the internet all fail. It tests the topology the deployment must reproduce; the production network policy and image are not built yet.

## Not here yet

A process entry point and token acquisition for the worker (client credentials with a signed JWT against the identity provider), the production image, a real classifier, the fixture servers of WP-1.12 and the recursion-style schema complexity limits of docs/mcp-compatibility.md beyond depth and node counts.

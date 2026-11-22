# Performance and Capacity Test Plan

| | |
|---|---|
| Version | 0.1 (proposal; closes gap D6 in `docs/reviewgap.md`) |
| Depends on | `Plan/functional-spec.md` v0.7 (NFR-1..5, Section 9 method), `docs/testing/cases.md` v0.5 (TC-Z14, Z15, Z18, Z4, Z17, Z16), `docs/deployment-architecture.md` v0.4 (Section 8), `docs/parameter-register.md` v0.3 |
| Status | **Every value below is a proposal**. No hardware class, payload mix or workload has been agreed, and nothing has been measured. The figures define what a first load test should use so results are comparable; they are not claims about the product. |

## 1. Purpose

Give the non-functional cases (TC-Z14 latency and throughput, TC-Z15 classifier tiering, TC-Z18 scale and soak, TC-Z4 hostile large or slow responses, TC-Z16 availability, TC-Z17 disaster recovery) a defined environment, workload and measurement method so that targets NFR-1 to NFR-5 can be accepted or rejected on evidence.

## 2. Reference environment (proposal)

| Item | Proposal | Reason |
|---|---|---|
| Cluster | One Kubernetes cluster, three zones, node pools as in `docs/deployment-architecture.md` Section 3.2 | Matches production topology |
| Gateway pod | Fixed resource requests and limits recorded in the report (starting point: 2 vCPU and 4 GiB per pod, to be tuned), 3 replicas minimum | Latency target is stated per instance; resources must be fixed to compare runs |
| Policy engine | Sidecar in each gateway pod with the production policy bundle | Hot-path component |
| Registry and database | Database with synchronous replica, production-shaped data (see 3.3) | Cache misses hit it |
| Upstream | Mock MCP server with configurable latency (0 ms for added-latency measurement) | Isolates platform overhead |
| Load generator | Separate nodes from the system under test | Avoids contention |
| Observability | OpenTelemetry spans at gateway entry and exit; metrics for CPU, memory, queue depths | Added latency is derived from spans |
| Clock and warm-up | Time-synchronised nodes; 5-minute warm-up discarded | Stable numbers |

The report must state cloud, instance types, Kubernetes version, container runtime, network plugin, and software versions.

## 3. Workload model (proposal)

### 3.1 Request mix
| Call type | Share | Notes |
|---|---|---|
| `tools/list` | 10% | Filtered and hash-checked |
| `tools/call` read | 60% | Typical |
| `tools/call` write or execute | 25% | Includes argument guards and DLP |
| `tools/call` needing approval | 1% | Held, not counted in latency of other calls |
| Denied calls (policy, hash, limits) | 4% | Fast path |

### 3.2 Payloads
Request arguments 0.5 KB median, 4 KB 95th percentile, 16 KB maximum; responses 2 KB median, 64 KB 95th percentile, up to the configured response limit for hostile cases; 5% of responses contain markup or JSON that exercises response inspection; 1% contain matches for DLP rules.

### 3.3 Registry data
1,000 agents, 200 servers, 5,000 tools, 20 tenants (one at 10 times average size), 5 million audit events preloaded.

### 3.4 Concurrency
Sessions ramp to the target (NFR-5: 10,000 concurrent sessions, 5,000 calls per second cluster-wide); per-instance runs at 1,000 requests per second (NFR-1). Arrival is open-loop (constant rate with Poisson variation) so latency under overload is visible.

## 4. Test types and pass criteria

| Case | Procedure | Pass criteria (from the specification) |
|---|---|---|
| TC-Z14 | 30 minutes steady state at 1,000 req/s per instance with all deterministic stages on; also 50% and 150% | Added latency p95 at most 25 ms and p99 at most 60 ms at the target rate |
| TC-Z15 | Same with classifier tier on: inline mode and asynchronous mode | Inline classifier p95 at most 150 ms or asynchronous with no added latency; deterministic tier within its budget |
| TC-Z18 | Ramp to 10,000 sessions and 5,000 calls/s, hold 1 hour, then 6-hour soak; kill a node and a zone during the run | Targets held; error rate and memory within bounds set in advance; no policy bypass; fail-closed behaviour confirmed |
| TC-Z4 | 500 hostile sessions (huge and slow responses) beside normal load | Normal traffic latency within 2 times the baseline; memory bounded |
| TC-Z16 | Synthetic probes from three zones over the agreed period | 99.95% monthly availability |
| TC-Z17 | Timed failover exercise | RPO at most 5 minutes, RTO at most 30 minutes, audit chain verifies |

"Bounds set in advance" means the report fixes error-rate and memory limits before the run; they are not yet defined.

## 5. Measurement method

- Added latency = gateway span duration minus upstream time, measured per request, reported as p50, p95, p99, p99.9 with confidence intervals from at least three runs.
- Report CPU and memory per pod, policy engine latency, cache hit rate, database query time and outbox lag.
- Compare each run with the previous release candidate; a regression above an agreed percentage fails the run (percentage to be set).
- Raw data and scripts are stored with the report so another team can repeat the run.

## 6. Security implications of the performance choices

| Choice | Benefit | Security consequence |
|---|---|---|
| Decision cache | Lower latency | Stale decisions within the TTL; keyed on bundle hash and input digest so a policy change invalidates it |
| Registry and definition cache (60 s) | Fewer lookups | Bounded drift window, closed at call time by the hash check (FR-DRIFT-7) |
| Inline versus asynchronous inspection | Lower latency | Asynchronous results cannot block the current call; high-impact decisions never depend on them |
| Response size cap | Protects capacity | Truncation or blocking can hide content; policy decides by classification |
| Fail-closed on dependency loss | Safety | Outage becomes business outage; sizing must include failure of one zone |

## 7. Open items

- Approve or change the proposed environment and workload (parameter PAR-O-25).
- Decide error-rate and memory bounds, regression percentage and the observation period for availability.
- Build the load generator and mock upstream (Phase 1 harness work extended in Phase 2).
- Replace proposed pod sizes with measured values.

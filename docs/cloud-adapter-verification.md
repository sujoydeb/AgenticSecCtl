# Cloud Adapter Verification: AWS, Azure, Google Cloud

| | |
|---|---|
| Version | 0.2 (partial; advances gap E4 in `docs/reviewgap.md`: AWS extended, Azure and Google Cloud first pass) |
| Depends on | `docs/deployment-architecture.md` v0.4 (Sections 4, 5, 6, 12), `Plan/architecture.md` v0.6 (Section 8), `controls/catalogue.md` v0.6 (CTL-08, CTL-13, CTL-24, CTL-30), `docs/ci-cd-pipeline.md` v0.8 |
| Scope | AWS (first example adapter, extended in v0.2), Azure (AKS, first pass) and Google Cloud (GKE, first pass, search summaries only). The cloud choice itself is still open (customer input CI-6). |
| Evidence | AWS and Azure: documentation search result chunks read on 2026-11-22 through the AWS documentation tool and the Microsoft Learn search tool (chunks, not full pages). Google Cloud: web search result summaries only; Google pages were not read directly and one claim rests on a third-party blog. Anything not listed as verified remains **[VERIFY]**. |

## 1. Verified capabilities and what they mean for the design

| Design need | AWS capability | Status | Design implication | Source |
|---|---|---|---|---|
| Block pods and servers from the instance metadata service (threat H, TC-H1, TC-I4) | IMDSv2 can be required per instance or launch template (`HttpTokens=required`). For container environments the documentation recommends a hop limit of 2 when IMDSv2 is required | Verified (documentation) | Requiring IMDSv2 is not enough. The recommended hop limit of 2 for containers lets pods reach the metadata service, so pod access must be blocked by other means: network policy or node-level rules, and workload identity (below) so that pods do not need node credentials. Which combination blocks pod access without breaking node components must be tested on EKS | [EC2 instance metadata options](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-new-instances.html) |
| Evidence and anchor storage that cannot be altered (CTL-13, FR-AUD-4, NFR-6) | S3 Object Lock: write-once-read-many; retention periods in governance or compliance mode, plus legal holds; works only on buckets with versioning; compliance mode cannot be removed by any user including the root user; Object Lock has been assessed by an outside firm for certain US financial-record rules | Verified (documentation) | Use compliance mode for anchors in a separate account; use legal hold for FR-ADM-7 holds; remember versioning is mandatory; retention length is a legal decision (parameter register). Cross-region replication behaviour of locked objects is not verified here | [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html), [S3 FAQ](https://aws.amazon.com/s3/faqs/) |
| Workload identity without static keys (FR-KEY-2, NFR-9) | EKS Pod Identity associates an IAM role with a Kubernetes service account; credentials are temporary and rotated automatically; supports a target role in another account; associations are eventually consistent and should not sit in critical paths | Verified (documentation) | Use one service account and role per platform workload; do not change associations on hot paths; cross-account target roles suit the separate anchor account | [Pod Identity target roles](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-assign-target-role.html), [cmdlet reference](https://docs.aws.amazon.com/powershell/v5/reference/items/New-EKSPodIdentityAssociation.html) |
| Default-deny network policy (CTL-08, TC-X2) | The VPC CNI plugin enforces Kubernetes network policies (needs EKS 1.25 or later and VPC CNI 1.14.0 or later). In the default "standard" mode pods start with allow-all until policies are applied; in "strict" mode pods start with default deny, DNS must be explicitly allowed, node addresses are allowed for health probes, and host-network pods are not covered | Verified (documentation) | The design's default-deny rule needs **strict mode** (or an equivalent mechanism), otherwise new pods have a window with no restrictions. Add explicit DNS allow rules; do not rely on policies for host-network pods | [Network policy configuration](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy-configure.html), [troubleshooting article](https://repost.aws/articles/ARq5x53--OSPihwF3Y8C50wg/troubleshooting-kubernetes-network-policies-enforcing-policies-in-amazon-eks) |
| Highly available relational database with failover (CTL-24, NFR-3, NFR-4) | RDS for PostgreSQL Multi-AZ keeps a synchronous standby in another zone with automatic failover; this protects against zone failure, not region failure; point-in-time restore is documented for Multi-AZ DB clusters | Verified (documentation) | Matches the design's synchronous replica; cross-region replicas and PITR parameters must be chosen separately. Row-level security and insert-only roles are PostgreSQL features and were not verified for this service | [RDS DR strategies](https://docs.aws.amazon.com/prescriptive-guidance/latest/dr-standard-edition-amazon-rds/sites-strategies.html), [PITR for Multi-AZ clusters](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.MultiAZDBCluster.html) |
| Private connectivity to managed services (deployment Section 4) | Interface VPC endpoints (PrivateLink) for Secrets Manager; endpoint policies; resource policies can require requests to come through the endpoint | Verified for Secrets Manager only | Use endpoints and endpoint conditions for the secrets manager; KMS, S3, IdP and SIEM endpoints were not verified | [Secrets Manager VPC endpoint](https://docs.aws.amazon.com/secretsmanager/latest/userguide/vpc-endpoint-overview.html) |

## 2. Not verified for AWS (still **[VERIFY]**)

- Sandboxed runtimes on EKS: see Section 2A (a Nitro Sandbox feature was found; gVisor and Kata not checked); compatibility with the actual server workloads is untested.
- Admission engines (Kyverno, Gatekeeper) on EKS and signature verification integration.
- KMS key policies for per-tenant keys and HSM options (multi-region keys: see Section 2A).
- Bucket-policy patterns for write-only anchor credentials (Object Lock with replication: see Section 2A).
- Egress controls: NAT, egress proxy patterns, DNS firewall, and WAF options for the dashboard.
- Aurora versus RDS choices for row-level security and audit role separation; cross-region replica lag.
- Load balancer options for the internal gateway endpoint and global traffic management for failover.
- Costs and quotas.

## 2A. Additional AWS facts read on 2026-11-22 (v0.2)

| Design need | AWS capability (as stated in the chunk read) | Design implication | Source |
|---|---|---|---|
| Sandboxed MCP server pods (CTL-11) | Amazon EKS "isolated and confidential pods" run each pod in its own Nitro Sandbox, selected per pod with `runtimeClassName` (`isolated-sandbox` or `confidential-sandbox`); needs Kubernetes 1.36 or later and supported EC2 instance types; designed to run untrusted container images but not untrusted pod specs (pod spec authorship must be restricted with RBAC and admission control) | A candidate sandbox for the server pool on EKS; the platform must still restrict who can set the runtime class. Compatibility with MCP server workloads and stdio wrappers is untested | EKS user guide, "Sandboxing on Amazon EKS", "Security model" |
| Per-tenant keys across regions (CTL-30, DR) | KMS multi-Region keys: a primary key and replicas in other Regions of the same partition share key ID, material, rotation status and origin; replicas are independent resources with their own key policy, grants and state; an existing single-Region key cannot be converted | Decide multi-Region at key creation; key policy changes must be applied to every replica (they do not propagate) | AWS Security Blog on multi-Region keys; KMS `ReplicateKey` reference; Identity Center blog note |
| Evidence and anchors replicated to a second region (CTL-13, DR) | S3 replication copies Object Lock retention and legal-hold state; source and destination buckets must both have Object Lock enabled; the replication role needs `s3:GetObjectRetention` and `s3:GetObjectLegalHold` on the source | Anchor and evidence buckets can be replicated while keeping retention; the replication role is a sensitive identity | S3 user guide, "Object Lock considerations"; "What does Amazon S3 replicate?" |

## 3. Consequences recorded elsewhere

| Finding | Where it should be reflected | Status |
|---|---|---|
| Strict network policy mode is needed for default deny | `docs/deployment-architecture.md` Section 4.2 and DA-1, DA-2 | Added in deployment v0.3 |
| IMDS hop limit guidance conflicts with blocking pods | `docs/deployment-architecture.md` Section 4.2 | Added in deployment v0.3 |
| Object Lock needs versioning and compliance mode for anchors | `docs/deployment-architecture.md` Section 6.2 | Added in deployment v0.3 |
| Pod Identity associations are eventually consistent | `docs/deployment-architecture.md` Section 5 | Added in deployment v0.3 |

## 4. Azure (AKS) first pass, read 2026-11-22

| Design need | Azure capability (as stated in the chunk read) | Status | Design implication | Source |
|---|---|---|---|---|
| Metadata endpoint hardening (threat H, TC-H1, TC-I4) | All pods can reach IMDS at 169.254.169.254 by default; guidance is a network policy that blocks pod egress to it (needs a network policy engine); a separate **preview** setting blocks IMDS for non-host-network pods, after which workloads must use Entra Workload ID; node reimage is needed to apply it | Read; preview feature not for production | Use the network-policy path, and treat the cluster-level setting as an optional extra once it is generally available | AKS best practices (cluster security), "Block pod access to IMDS (preview)" |
| Immutable evidence storage (CTL-13, FR-AUD-4) | Blob immutable storage: time-based retention (1 day to 146,000 days) and legal holds, container-level or version-level; unlocked policies give no delete protection, a locked policy gives it; a container-level legal hold needs tags; incompatible with point-in-time restore of the storage account; not supported with NFS 3.0 or SFTP; version-level time-based retention needs versioning | Read | Anchors need a **locked** policy (as with Object Lock compliance mode); no storage-level restore feature, rely on separate copies | Azure Storage immutable storage pages |
| Workload identity (FR-KEY-2) | Microsoft Entra Workload ID uses projected service account tokens and OIDC federation; the pod gets a federated credential bound to namespace and service account; limit of 20 federated credentials per managed identity (identity bindings address it); default audience `api://AzureADTokenExchange`; Entra tokens last 24 hours | Read | Matches the design; the 24 hour token lifetime exceeds the platform's 10 minute target for access tokens, so the broker must not hand these out as upstream credentials | AKS Workload ID pages |
| Default-deny network policy (CTL-08, TC-X2) | All pod traffic allowed by default; three engines (Cilium, Azure NPM, Calico); Cilium recommended for Linux, supports L7 and FQDN policy; **Azure NPM is legacy: Windows support ended 2026-09-30, Linux ends 2028-09-30**; a default-deny egress policy also blocks DNS, so DNS must be allowed explicitly | Read | Choose Cilium; add DNS allow rules to the default-deny baseline (the deployment document must say so for every cloud) | AKS network policy pages |
| Managed PostgreSQL HA and PITR (CTL-24, NFR-3, NFR-4) | Flexible server: zone-redundant HA with synchronous standby, failover in 60 to 120 seconds with no data loss; same-zone option; PITR creates a **new** server, restores HA servers as single instances; retention 7 to 35 days default 7; HA does not protect against logical errors; geo-redundant backup and cross-region replica options (replica RPO up to five minutes) | Read | The platform RPO of 5 minutes holds within a region; cross-region needs geo-restore or a replica with possible data loss. Restore is a new server, so the runbook must include repointing | Azure PostgreSQL HA, backup and business continuity pages |
| Sandboxed server pods (CTL-11) | Pod sandboxing runs each pod in a Kata-based pod VM with its own guest kernel on Azure Linux node pools (generation 2 VMs, nested virtualisation); a newer variant is preview; no FIPS or Trusted Launch on those pools; Defender for Containers does not assess Kata pods; privileged pods are allowed but isolated; `hostPath` should be blocked by policy; docs say it does not isolate the control plane or cluster admins | Read | Candidate sandbox; note the missing Defender coverage and the single OS restriction | AKS pod sandboxing pages |
| Private connectivity, admission, per-tenant keys, egress controls, WAF, costs | Not read | **[VERIFY]** | | |

## 5. Google Cloud (GKE) first pass, from search summaries only (2026-11-22)

| Design need | Capability (as summarised) | Status | Design implication |
|---|---|---|---|
| Metadata and workload identity | Workload Identity Federation for GKE runs a metadata server on each node that intercepts credential requests and exchanges a Kubernetes token for short-lived credentials; it replaces metadata concealment; sandbox-enabled nodes block regular pods from cluster metadata by default, and the docs advise a network policy blocking 169.254.169.254 with Workload Identity; a third-party report from an older version says a sandbox did not block metadata as documented | Summary only; pages not read | Add the network-policy block and test it from a sandboxed pod (TC-H1, TC-I4) rather than trusting the documentation |
| Sandbox | GKE Sandbox (gVisor) exists; scope and limits not read | Summary only | **[VERIFY]** |
| Immutable storage (CTL-13) | Bucket retention policy with lock: once locked it cannot be removed or shortened (it can be extended), and a bucket with a locked policy cannot be deleted until objects meet retention; object holds; a per-object retention lock; the provider cites an external assessment for SEC 17a-4(f), FINRA and CFTC | Summary only | Locked retention policy is the counterpart of Object Lock compliance mode |
| Managed PostgreSQL HA and PITR | Cloud SQL regional HA and PITR exist as separate settings; details not found | Not verified | **[VERIFY]** |
| Default-deny network policy on GKE | Not found (no Dataplane V2 or default-deny statements located) | Not verified | **[VERIFY]** |

## 6. Consequences recorded elsewhere (continued)

| Finding | Where it should be reflected | Status |
|---|---|---|
| A default-deny egress policy blocks DNS; allow cluster DNS explicitly | `docs/deployment-architecture.md` Section 4.2 | Added in deployment v0.4 |
| Pod identity tokens are not upstream credentials (Entra tokens last 24 hours) | `docs/deployment-architecture.md` Section 5 | Added in deployment v0.4 |
| Locked (not merely configured) immutable retention is required on every cloud | `docs/deployment-architecture.md` Section 6.2 | Added in deployment v0.4 |
| Restore creates a new database server; the runbook must cover repointing | `docs/runbooks/operational-runbook.md` | Recorded here only; runbook not changed |

## 7. Next steps

- Confirm the first cloud (customer input CI-6) and complete its table; read the Google Cloud pages directly (Section 5 rests on search summaries).
- Test the metadata-blocking combination and strict network policy on a real EKS cluster before relying on them (TC-H1, TC-I4, TC-X2).
- Record the verified adapter facts in the deployment document and the parameter register.

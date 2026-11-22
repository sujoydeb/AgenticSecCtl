# Cloud Adapter Verification: AWS

| | |
|---|---|
| Version | 0.1 (partial; closes the AWS part of gap E4 in `docs/reviewgap.md`) |
| Depends on | `docs/deployment-architecture.md` v0.3 (Sections 4, 5, 6, 12), `Plan/architecture.md` v0.4 (Section 8), `controls/catalogue.md` v0.3 (CTL-08, CTL-13, CTL-24, CTL-30), `docs/ci-cd-pipeline.md` v0.3 |
| Scope | One cloud (AWS) used as the first example adapter. Azure and Google Cloud are **not verified**. The cloud choice itself is still open (customer input CI-6). |
| Evidence | AWS documentation search results read on 2026-11-22 through the AWS documentation tools (verbatim page chunks, not the full pages). The chunk quoted or summarised is named in the Source column. Anything not listed as verified remains **[VERIFY]**. |

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

- Sandboxed runtimes (gVisor, Kata or microVM-based isolation) on EKS node types and their compatibility with the server workloads.
- Admission engines (Kyverno, Gatekeeper) on EKS and signature verification integration.
- KMS key policies and multi-region keys for per-tenant keys; HSM options.
- S3 Object Lock with cross-region replication, and access-point or bucket-policy patterns for write-only anchor credentials.
- Egress controls: NAT, egress proxy patterns, DNS firewall, and WAF options for the dashboard.
- Aurora versus RDS choices for row-level security and audit role separation; cross-region replica lag.
- Load balancer options for the internal gateway endpoint and global traffic management for failover.
- Costs and quotas.

## 3. Consequences recorded elsewhere

| Finding | Where it should be reflected | Status |
|---|---|---|
| Strict network policy mode is needed for default deny | `docs/deployment-architecture.md` Section 4.2 and DA-1, DA-2 | Added in deployment v0.3 |
| IMDS hop limit guidance conflicts with blocking pods | `docs/deployment-architecture.md` Section 4.2 | Added in deployment v0.3 |
| Object Lock needs versioning and compliance mode for anchors | `docs/deployment-architecture.md` Section 6.2 | Added in deployment v0.3 |
| Pod Identity associations are eventually consistent | `docs/deployment-architecture.md` Section 5 | Added in deployment v0.3 |

## 4. Azure and Google Cloud

Not started. For each, repeat the table in Section 1: metadata endpoint hardening, immutable storage, workload identity, default-deny network policy on the managed Kubernetes service, managed PostgreSQL high availability and PITR, private connectivity, sandboxed runtimes, admission control. Use the vendor's own documentation (for Microsoft and Azure, Microsoft Learn).

## 5. Next steps

- Confirm the first cloud (customer input CI-6) and complete its table.
- Test the metadata-blocking combination and strict network policy on a real EKS cluster before relying on them (TC-H1, TC-I4, TC-X2).
- Record the verified adapter facts in the deployment document and the parameter register.

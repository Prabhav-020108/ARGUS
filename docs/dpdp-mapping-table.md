# DPDP Rule 6/7/8/15 Mapping Table (DRAFT — needs mentor/legal review)

One row per checkable technical fact. This table is literally the Rego-writing
checklist for Phase 4 — one deny rule per row.

| # | DPDP Rule | Checkable Technical Fact | Cartography Field(s) Needed (confirm against graph/schema.md) | Notes |
|---|---|---|---|---|
| 1 | Rule 6(1)(a) — encryption | S3 bucket must have server-side encryption enabled | AWSS3Bucket encryption-related properties | Matches the `s3_disable_encryption` mutator built in Part K; UNVERIFIED - no S3 instances synced yet |
| 2 | Rule 6(1)(a) — encryption at rest | RDS instance must have storage encryption enabled | AWSRDSInstance.storage_encrypted | Only relevant if RDS is in scope; UNVERIFIED - no RDS instances synced yet |
| 3 | Rule 6 — access control | Security group must not allow unrestricted ingress (0.0.0.0/0) on sensitive ports | AWSIpPermissionInbound range/fromport/toport + AWSIpRange for CIDR | Also a generic CIS-style check, not DPDP-specific |
| 4 | Rule 6 — access control (MFA) | Account-level MFA enforcement should be enabled | AWSAccount.account_mfa_enabled | account-level only; no per-user MFA field observed in the graph |
| 5 | Rule 6 — recoverability | S3 buckets holding personal data must have versioning enabled | AWSS3Bucket versioning-related property | Matches the `s3_disable_versioning` mutator; UNVERIFIED - no S3 instances synced yet |
| 6 | Rule 6 — public exposure | S3 bucket must not allow public access | AWSS3Bucket public-access-block properties | Matches the `s3_disable_public_access_block` mutator; UNVERIFIED - no S3 instances synced yet |
| 7 | Rule 6 — logging / auditability | S3 buckets must have access logging enabled | AWSS3Bucket logging-related property | UNVERIFIED - no S3 instances synced yet |
| 8 | Rule 7 — 72-hour breach notification readiness | Account-wide logging (CloudTrail) / threat detection (GuardDuty) must be enabled so a breach can even be detected in time | CloudTrail / GuardDuty nodes if ingested | NOT YET INGESTIBLE - cartography.json does not sync cloudtrail/guardduty |
| 9 | Rule 8 — retention / erasure | S3 buckets holding personal data must have a lifecycle expiration rule | AWSS3Bucket lifecycle-rule properties | UNVERIFIED - no S3 instances synced yet |
| 10 | Rule 15 — cross-border transfer | Flag (do not hard-fail) any resource holding personal data outside an approved region | AWSUser / AWSRole `.region` property | Rule 15 is permissive/negative-list — this is a dashboard **visibility** flag per the v3 design doc §3, not a violation |

## Review status
- [x] Field names cross-checked against `graph/schema.md`
- [ ] Mentor / legal-adjacent review pass completed

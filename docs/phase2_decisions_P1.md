# Phase 2 decisions: P1 (Graph Builder & AWS Data)

- Derived attack graph instead of raw Cartography: Cartography edges mean "belongs to", not "attacker can move".
- Trust edges reversed (principal -> role); service and root principals skipped.
- Deny statements ignored (stated limitation); Conditions, SCPs and permission boundaries not modeled.
- Dangerous-permissions list (privesc_actions.json) because Cartography stores only the current policy version, so the rollback attack is invisible.
- Canonical AWS-prefixed labels only, to avoid double-counting nodes with both label families.
- Inbound security-group rules only: default egress 0.0.0.0/0 exists on every group and would make all of them look exposed.
- ICMP rules ignored (no service port); IPv6 ::/0 treated as internet.
- Added SG_TO_VPC edges (listed in the contract) which introduces node kind `vpc`; P2 and P3 informed.
- Principals from other accounts have no node, so trust edges to them are skipped.
- Test buckets use "versioning never enabled" as the shared flaw because S3 default encryption makes "encryption off" impossible.
- Key-based entry: a listed user with an active key is seeded through the key node, so paths start at the key.
- Surprises from the verified-facts sheet:
  - S3 bucket tags (`contains_personal_data=true`) applied in AWS via `put-bucket-tagging` are not synced into Neo4j by Cartography (neither as `AWSTag` nodes nor as properties on `AWSS3Bucket`), requiring the manual fallback list `crown_jewel_ids` in `risk/config.json`.
  - `AWSIpPermissionInbound` omits `fromport` and `toport` keys completely when all ports are allowed (protocol `"-1"`), encoding them as `NoneNone-1` in `ruleid`.
  - `action` and `resource` fields on `AWSPolicyStatement` nodes are stored as lists of strings (`List<String>`) rather than single strings, even when specifying a single wildcard (`["*"]`).
  - Principals carry multiple simultaneous labels (e.g. `["AWSPrincipal", "AWSUser", "UserAccount"]` and `["AWSPrincipal", "AWSRole", "PermissionRole"]`).

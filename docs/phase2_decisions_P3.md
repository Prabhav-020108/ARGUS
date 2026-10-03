# Phase 2 - P3 Decisions

## Weights meeting (Day 4)
- Date: 2026-10-02
- Attendees: Prabhav (P1), Shaurya (P2), Yashraj (P3)
- Numbers challenged and by whom: P1 challenged `sg_to_vpc` (0.2) and `net_sensitive_port` (0.9); P2 challenged `can_assume` (0.6) vs `direct_admin` (1.0).
- Changes made: Retained coarse heuristic values (0.2, 0.4, 0.6, 0.9); PassRole kept at 0.4 due to requiring separate compute privileges.
- Frozen on (date): 2026-10-02

## Crown jewels (S3)
- Decision: crown_jewel_ids lists the two test buckets by name (`argus-test-pii-near-pb3882`, `argus-test-pii-far-pb3882`).
- Why: P1 verified S3 bucket tags are not stored in Neo4j, so the tag-based crown_jewel_tag lookup cannot work; manual fallback per Loophole L6.
- Source: reported by P1.

## Verified facts from P1
1. Cartography stores IAM statement action and resource as List<String>.
2. All-traffic security-group rules omit fromport/toport (None/absent, protocol "-1").
3. S3 bucket tags are NOT stored in Neo4j, so the two test bucket names `argus-test-pii-near-pb3882` and `argus-test-pii-far-pb3882` must be added to crown_jewel_ids in `risk/config.json`.

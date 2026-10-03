# Phase 2 - P3 Decisions

## Weights meeting (Day 4)
- Date: 
- Attendees: 
- Numbers challenged and by whom: 
- Changes made: 
- Frozen on (date): 

## Crown jewels (S3)
- Decision: crown_jewel_ids lists the two test buckets by name (`argus-test-pii-near-pb3882`, `argus-test-pii-far-pb3882`).
- Why: P1 verified S3 bucket tags are not stored in Neo4j, so the tag-based crown_jewel_tag lookup cannot work; manual fallback per Loophole L6.
- Source: reported by P1.

## Verified facts from P1
1. Cartography stores IAM statement action and resource as List<String>.
2. All-traffic security-group rules omit fromport/toport (None/absent, protocol "-1").
3. S3 bucket tags are NOT stored in Neo4j, so the two test bucket names `argus-test-pii-near-pb3882` and `argus-test-pii-far-pb3882` must be added to crown_jewel_ids in `risk/config.json`.

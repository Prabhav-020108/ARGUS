# Privacy Receipt Schema

Written for every finding, every tier, every outcome. This is what the
Privacy Receipt Viewer (Phase 8) renders directly.

- `finding_id`, `rule_id` — which check triggered this
- `projected_fields: { attr: value, ... }` — only what `rule_id` declares it reads
- `tokens: { BUCKET_3: <vault-ref>, ... }` — never the real value, inline
- `scrub_result: { presidio_hits: 0, secret_scan_hits: 0 }`
- `tier_used: T0 | T1 | T2`
- `leaked_to_network: false` — true only if T2 fired
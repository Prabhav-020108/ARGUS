# Decisions & Rationale Log

One entry per non-obvious choice. Future-you (and the paper's Related
Work / Methodology sections) will thank present-you for this.

## 2026-09-28 — Scoped Cartography sync modules
**Decision:** Scoped cartography sync to iam,ec2,kms,s3,rds.
**Why:** Faster runs, covers Phase 1-2 needs; reduces noise from unused service types.
**Alternatives considered:** Full sync (all modules) — too slow and pulls in unrelated resources.

## 2026-09-28 — IAM user instead of role for scanner
**Decision:** Using an IAM user (argus-cartography-scanner) with SecurityAudit instead of a role.
**Why:** Simpler for Phase 1; avoids cross-account assume-role setup overhead.
**Alternatives considered:** AssumeRole from a Lambda/EC2 — to be revisited before the Phase 4 least-privilege test.

## 2026-09-28 — Interdiction MILP as primary prioritizer
**Decision:** Interdiction MILP replaces Stackelberg as the primary prioritizer.
**Why:** Patching is a binary decision (patch or not), which maps cleanly to binary ILP; Stackelberg is better suited to continuous strategy games.
**Alternatives considered:** Stackelberg game — see v3 doc section 7.4 for full comparison.
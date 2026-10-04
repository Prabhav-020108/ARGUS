# Phase 4 decisions - Privacy Airlock & Policy-as-Code

Kept in its own file (not appended to docs/decisions-log.md) so the Phase 3 branch and the Phase 4
branch never edit the same file. Fold these into decisions-log.md in the post-merge cleanup.

## 2026-10-04 - Projection fields are derived from the Rego source
**Decision:** privacy/airlock/projection.py reads every `input.resource.<field>` reference in a rule's
.rego file (comments stripped) and uses exactly that set as the allowed fields for that rule_id.
**Why:** one declaration, two uses (design doc 18.4): the compliance check and the privacy boundary can never
drift apart. Convention enforced by tests: one `# rule_id:` header per file, attributes read only as
`input.resource.<field>`.
**Alternatives considered:** a hand-maintained allowed_fields map (two lists that drift).

## 2026-10-04 - Presidio used through its PatternRecognizer layer, no spaCy model
**Decision:** Presidio PatternRecognizers (email, Aadhaar, PAN, Indian mobile, payment card) run directly
on text; the spaCy NLP engine and PERSON/LOCATION NER are NOT used. If presidio-analyzer cannot be imported,
identical regexes run through plain `re` (fallback), so the check is never silently lost.
**Why:** offline, no 400 MB model download, and NER would false-positive on structured tokens like BUCKET_1.
Presidio's anonymizer package is not needed: ARGUS does its own redaction/tokenization.
**Limitation to state in the paper:** names of people in free text are not detected; the default-deny projection
(free text is never included) is the real control, scrubbing is a second layer.

## 2026-10-04 - Aadhaar and PAN are format-only checks
**Decision:** no Verhoeff checksum on Aadhaar. **Why:** this is a BLOCKING control, so fake or mistyped numbers
must be caught too (canary data is fake by design). Cost: some false positives, which only cause a redaction.

## 2026-10-04 - Vault encryption uses Fernet over SQLite, not SQLCipher
**Decision:** each real value is Fernet-encrypted before it is written to SQLite. Key from env ARGUS_VAULT_KEY or
a git-ignored key file (privacy/vault/.vault.key, auto-created). **Why:** sqlcipher3 has no reliable Windows wheel
for Python 3.13; `cryptography` is already a project dependency. Metadata (token names, kinds, timestamps) is not
encrypted; real values are.

## 2026-10-04 - Tokens: per-record numbering, vault_refs make them unambiguous
BUCKET_1 restarts at 1 for every record. The `vault_refs` map (token -> random ref) returned by tokenize() is what
rehydrate() and the leak-check use, so two records can both contain BUCKET_1 without colliding.
Public constants pass through: 0.0.0.0/0, ::/0, AWS-managed policy ARNs. IPv6 other than ::/0 is NOT tokenized
(documented limitation; the default-deny projection keeps such fields out unless a rule reads them).

## 2026-10-04 - Leak-check scans keys, values, base64-decoded chunks and sibling-joined strings
Field-split detection is best effort (it joins sibling strings of the same dict/list). It reports counts only,
never the matched text.

## 2026-10-04 - IAM guard: forbidden list fails, watchlist warns
The scanner uses AWS's SecurityAudit managed policy, which is not perfectly control-plane-only. It contains
`rds:DownloadDBLogFilePortion`, `cognito-idp:ListUsers`/`ListUsersInGroup`, `identitystore:ListUsers` and
`s3:ListBucket` (object key names). These are on a WATCHLIST: reported as warnings, not failures. State this
honestly in the paper's limitations, or replace SecurityAudit with a custom policy later.
The live check is opt-in (ARGUS_LIVE_IAM_CHECK=1); the offline logic is always tested.

## 2026-10-04 - DPDP rules that depend on data Cartography does not provide
* `dpdp.rule6_versioning`: Cartography 0.141.0 omits `versioning_status` for never-versioned buckets, so a MISSING
  value is treated as "not enabled" (matches the near/far test buckets).
* `personal_data`, `has_lifecycle_expiration`, `approved_regions`, `cloudtrail_enabled`, `guardduty_enabled` are
  DERIVED fields the Phase 7 finding builder must supply (they are not Cartography properties).
* `dpdp.rule7_detection` only denies on an explicit `false`, so missing CloudTrail/GuardDuty data never raises a
  false alarm (those modules are not synced yet).
* `dpdp.rule15_region` emits `warn`, never `deny` (Rule 15 is permissive; visibility flag only).
* Rows 3 and 6 exist in BOTH libraries on purpose (`cis.*` and `dpdp.*`), so the dashboard can show the DPDP lens.

## Raw finding contract (input to run_airlock)
```
{"finding_id": "F-0001", "resource_id": "<real id or name>", "resource_type": "AWSS3Bucket",
 "attributes": {<every known property of the resource, plus derived fields>}}
```
Receipt = docs/privacy-receipt-schema.md plus three additive keys: `record_sha256`, `leak_check`, `blocked`.
`tier_used` is None at airlock time; the Phase 7 pipeline sets it, and sets `leaked_to_network` true only if T2 fires.

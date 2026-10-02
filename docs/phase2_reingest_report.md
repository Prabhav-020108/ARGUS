# Phase 2 Cartography Re-ingest Report

**Execution Date:** 2026-10-02  
**Target AWS Account:** `306255359620`  
**Ingestion Engine:** Cartography via WSL Ubuntu (`--selected-modules aws`)  
**Target Graph Database:** Neo4j Community `bolt://localhost:7687`

---

## 1. Before and After Counts

| Metric | Before Count (Step 3.1) | After Count (Step 3.3) | Change | Notes |
|---|---|---|---|---|
| **Total Nodes (`MATCH (n)`)** | 320 | 380 | +60 | Ingested S3 buckets, IAM user/roles, policies, statements, and network components |
| **S3 Buckets (`AWSS3Bucket`)** | 0 | 2 | +2 | `argus-test-pii-near-pb3882` and `argus-test-pii-far-pb3882` |
| **IAM Roles (`AWSRole`)** | 3 | 5 | +2 | `argus-test-role-a` and `argus-test-role-b` added |

---

## 2. Ingested `argus-test-*` Resources

### S3 Buckets (`AWSS3Bucket`)
- `argus-test-pii-near-pb3882`
- `argus-test-pii-far-pb3882`

### IAM User (`AWSUser`)
- `argus-test-user` (`arn:aws:iam::306255359620:user/argus-test-user`)

### IAM Roles (`AWSRole`)
- `argus-test-role-a` (`arn:aws:iam::306255359620:role/argus-test-role-a`)
- `argus-test-role-b` (`arn:aws:iam::306255359620:role/argus-test-role-b`)

### IAM Policies (`AWSPolicy`)
- `argus-test-read-near`
- `argus-test-read-far`

### Trust Relationships (`TRUSTS_AWS_PRINCIPAL`)
```
(:AWSRole {name: 'argus-test-role-a'})-[:TRUSTS_AWS_PRINCIPAL]->(:AWSUser {arn: 'arn:aws:iam::306255359620:user/argus-test-user'})
(:AWSRole {name: 'argus-test-role-b'})-[:TRUSTS_AWS_PRINCIPAL]->(:AWSRole {arn: 'arn:aws:iam::306255359620:role/argus-test-role-a'})
```

---

## 3. Observed `AWSS3Bucket` Property Keys

Raw output from `MATCH (b:AWSS3Bucket) RETURN keys(b) LIMIT 1;`:

```json
[
  "_module_name",
  "_module_version",
  "_ont_encrypted",
  "_ont_location",
  "_ont_name",
  "_ont_public",
  "_ont_source",
  "arn",
  "block_public_acls",
  "block_public_policy",
  "bucket_key_enabled",
  "creationdate",
  "default_encryption",
  "encryption_algorithm",
  "firstseen",
  "id",
  "ignore_public_acls",
  "lastupdated",
  "logging_enabled",
  "name",
  "object_ownership",
  "region",
  "restrict_public_buckets"
]
```

---

## 4. Verification Cypher Queries

### Verify Buckets
```cypher
MATCH (b:AWSS3Bucket) RETURN b.name;
```
**Output:**
```
"argus-test-pii-far-pb3882"
"argus-test-pii-near-pb3882"
```

### Verify Trust Relationships
```cypher
MATCH (r:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(p) 
WHERE r.name STARTS WITH 'argus-test' 
RETURN r.name AS role, p.arn AS principal;
```
**Output:**
```
role: "argus-test-role-a", principal: "arn:aws:iam::306255359620:user/argus-test-user"
role: "argus-test-role-b", principal: "arn:aws:iam::306255359620:role/argus-test-role-a"
```

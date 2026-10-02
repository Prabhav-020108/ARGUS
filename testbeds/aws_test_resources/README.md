# AWS test resources (near/far worked example)

Order a human should create things (admin profile, never the scanner):
1. IAM user `argus-test-user`
2. Two S3 buckets (near, far), then tag both `contains_personal_data=true`
3. Role A (`trust-a`), then policy `argus-test-read-near`, attach to role A
4. Role B (`trust-b`, trusts role A), then policy `argus-test-read-far`, attach to role B

Role A must exist before role B. Copy each `*.template.json` to `*.local.json`
and fill the placeholders. `*.local.json` is git-ignored. Never commit real ids.

Deletion steps: see `testbeds/argus_test_resources.md`.
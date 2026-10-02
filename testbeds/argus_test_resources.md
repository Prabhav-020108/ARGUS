# ARGUS test resources (near/far worked example)

Created with an admin profile for the Phase 2 worked example. Nothing here touches the CloudGoat scenario.

| Resource | Name |
|---|---|
| IAM user | argus-test-user |
| IAM role A | argus-test-role-a (trusts argus-test-user) |
| IAM role B | argus-test-role-b (trusts argus-test-role-a) |
| Managed policy | argus-test-read-near (s3:GetObject, s3:ListBucket on NEAR bucket) |
| Managed policy | argus-test-read-far (same on FAR bucket) |
| Bucket NEAR | argus-test-pii-near-pb3882 |
| Bucket FAR | argus-test-pii-far-pb3882 |

Both buckets are tagged contains_personal_data=true and never had versioning enabled
(the shared flaw; S3 default encryption makes "encryption off" impossible).

Paths: near = user > role A > policy > statement > bucket (4 hops).
far = user > role A > role B > policy > statement > bucket (5 hops).

## Deletion (after Phase 10, admin profile, replace ACC with the account id and fill bucket names)
    aws iam detach-role-policy --role-name argus-test-role-b --policy-arn arn:aws:iam::ACC:policy/argus-test-read-far
    aws iam delete-policy --policy-arn arn:aws:iam::ACC:policy/argus-test-read-far
    aws iam delete-role --role-name argus-test-role-b
    aws iam detach-role-policy --role-name argus-test-role-a --policy-arn arn:aws:iam::ACC:policy/argus-test-read-near
    aws iam delete-policy --policy-arn arn:aws:iam::ACC:policy/argus-test-read-near
    aws iam delete-role --role-name argus-test-role-a
    aws s3 rb s3://<NEAR> --force
    aws s3 rb s3://<FAR> --force
    aws iam delete-user --user-name argus-test-user
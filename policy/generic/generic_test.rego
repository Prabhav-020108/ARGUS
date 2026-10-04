package argus.generic_test

import data.argus.generic.iam_no_full_admin
import data.argus.generic.s3_default_encryption
import data.argus.generic.s3_public_access_block
import data.argus.generic.sg_open_ingress
import rego.v1

good_bucket := {
	"resource_type": "AWSS3Bucket",
	"default_encryption": true,
	"block_public_acls": true,
	"block_public_policy": true,
	"ignore_public_acls": true,
	"restrict_public_buckets": true,
}

test_public_access_block_pass if {
	count(s3_public_access_block.deny) == 0 with input as {"resource": good_bucket}
}

test_public_access_block_fail_one_flag if {
	bad := object.union(good_bucket, {"block_public_acls": false})
	count(s3_public_access_block.deny) == 1 with input as {"resource": bad}
}

test_public_access_block_fail_missing_flags if {
	count(s3_public_access_block.deny) == 4 with input as {"resource": {"resource_type": "AWSS3Bucket"}}
}

test_public_access_block_ignores_other_types if {
	count(s3_public_access_block.deny) == 0 with input as {"resource": {"resource_type": "AWSRole"}}
}

test_default_encryption_pass if {
	count(s3_default_encryption.deny) == 0 with input as {"resource": good_bucket}
}

test_default_encryption_fail if {
	bad := object.union(good_bucket, {"default_encryption": false})
	count(s3_default_encryption.deny) == 1 with input as {"resource": bad}
}

test_sg_open_ingress_pass_private_cidr if {
	rule := {"resource_type": "AWSIpPermissionInbound", "ip_range": "10.0.0.0/16", "protocol": "tcp", "fromport": 22, "toport": 22}
	count(sg_open_ingress.deny) == 0 with input as {"resource": rule}
}

test_sg_open_ingress_pass_world_open_web_port if {
	rule := {"resource_type": "AWSIpPermissionInbound", "ip_range": "0.0.0.0/0", "protocol": "tcp", "fromport": 443, "toport": 443}
	count(sg_open_ingress.deny) == 0 with input as {"resource": rule}
}

test_sg_open_ingress_fail_ssh if {
	rule := {"resource_type": "AWSIpPermissionInbound", "ip_range": "0.0.0.0/0", "protocol": "tcp", "fromport": 22, "toport": 22}
	count(sg_open_ingress.deny) == 1 with input as {"resource": rule}
}

test_sg_open_ingress_fail_all_traffic if {
	rule := {"resource_type": "AWSIpPermissionInbound", "ip_range": "0.0.0.0/0", "protocol": "-1"}
	count(sg_open_ingress.deny) == 1 with input as {"resource": rule}
}

test_iam_full_admin_fail if {
	stmt := {"resource_type": "AWSPolicyStatement", "effect": "Allow", "action": ["*"], "resource": ["*"]}
	count(iam_no_full_admin.deny) == 1 with input as {"resource": stmt}
}

test_iam_full_admin_pass_scoped if {
	stmt := {"resource_type": "AWSPolicyStatement", "effect": "Allow", "action": ["iam:Get*", "iam:List*"], "resource": ["*"]}
	count(iam_no_full_admin.deny) == 0 with input as {"resource": stmt}
}

test_iam_full_admin_pass_deny_effect if {
	stmt := {"resource_type": "AWSPolicyStatement", "effect": "Deny", "action": ["*"], "resource": ["*"]}
	count(iam_no_full_admin.deny) == 0 with input as {"resource": stmt}
}

package argus.dpdp_test

import data.argus.dpdp.rule15_region
import data.argus.dpdp.rule6_access_sg
import data.argus.dpdp.rule6_logging
import data.argus.dpdp.rule6_mfa
import data.argus.dpdp.rule6_public
import data.argus.dpdp.rule6_versioning
import data.argus.dpdp.rule6a
import data.argus.dpdp.rule6a_rds
import data.argus.dpdp.rule7_detection
import data.argus.dpdp.rule8_lifecycle
import rego.v1

good_bucket := {
	"resource_type": "AWSS3Bucket",
	"personal_data": true,
	"default_encryption": true,
	"encryption_algorithm": "AES256",
	"versioning_status": "Enabled",
	"logging_enabled": true,
	"has_lifecycle_expiration": true,
	"block_public_acls": true,
	"block_public_policy": true,
	"ignore_public_acls": true,
	"restrict_public_buckets": true,
}

# ---- row 1: Rule 6(1)(a) S3 encryption
test_rule6a_pass if {
	count(rule6a.deny) == 0 with input as {"resource": good_bucket}
}

test_rule6a_fail_not_encrypted if {
	bad := object.union(good_bucket, {"default_encryption": false})
	count(rule6a.deny) == 1 with input as {"resource": bad}
}

test_rule6a_fail_bad_algorithm if {
	bad := object.union(good_bucket, {"encryption_algorithm": "NONE"})
	count(rule6a.deny) == 1 with input as {"resource": bad}
}

# ---- row 2: RDS encryption
test_rule6a_rds_pass if {
	count(rule6a_rds.deny) == 0 with input as {"resource": {"resource_type": "AWSRDSInstance", "storage_encrypted": true}}
}

test_rule6a_rds_fail if {
	count(rule6a_rds.deny) == 1 with input as {"resource": {"resource_type": "AWSRDSInstance", "storage_encrypted": false}}
}

# ---- row 3: security group ingress
test_sg_pass if {
	rule := {"resource_type": "AWSIpPermissionInbound", "ip_range": "10.0.0.0/16", "protocol": "tcp", "fromport": 22, "toport": 22}
	count(rule6_access_sg.deny) == 0 with input as {"resource": rule}
}

test_sg_fail_rdp if {
	rule := {"resource_type": "AWSIpPermissionInbound", "ip_range": "0.0.0.0/0", "protocol": "tcp", "fromport": 3389, "toport": 3389}
	count(rule6_access_sg.deny) == 1 with input as {"resource": rule}
}

test_sg_fail_all_traffic if {
	rule := {"resource_type": "AWSIpPermissionInbound", "ip_range": "::/0", "protocol": "-1"}
	count(rule6_access_sg.deny) == 1 with input as {"resource": rule}
}

# ---- row 4: account MFA
test_mfa_pass if {
	count(rule6_mfa.deny) == 0 with input as {"resource": {"resource_type": "AWSAccount", "account_mfa_enabled": true}}
}

test_mfa_fail if {
	count(rule6_mfa.deny) == 1 with input as {"resource": {"resource_type": "AWSAccount", "account_mfa_enabled": false}}
}

# ---- row 5: versioning
test_versioning_pass if {
	count(rule6_versioning.deny) == 0 with input as {"resource": good_bucket}
}

test_versioning_fail_suspended if {
	bad := object.union(good_bucket, {"versioning_status": "Suspended"})
	count(rule6_versioning.deny) == 1 with input as {"resource": bad}
}

test_versioning_fail_when_status_missing if {
	bad := object.remove(good_bucket, ["versioning_status"])
	count(rule6_versioning.deny) == 1 with input as {"resource": bad}
}

test_versioning_ignores_non_personal_data_bucket if {
	other := object.remove(object.union(good_bucket, {"personal_data": false}), ["versioning_status"])
	count(rule6_versioning.deny) == 0 with input as {"resource": other}
}

# ---- row 6: public exposure
test_public_pass if {
	count(rule6_public.deny) == 0 with input as {"resource": good_bucket}
}

test_public_fail if {
	bad := object.union(good_bucket, {"restrict_public_buckets": false})
	count(rule6_public.deny) == 1 with input as {"resource": bad}
}

# ---- row 7: logging
test_logging_pass if {
	count(rule6_logging.deny) == 0 with input as {"resource": good_bucket}
}

test_logging_fail if {
	bad := object.union(good_bucket, {"logging_enabled": false})
	count(rule6_logging.deny) == 1 with input as {"resource": bad}
}

# ---- row 8: Rule 7 detection
test_rule7_pass_when_data_missing if {
	count(rule7_detection.deny) == 0 with input as {"resource": {"resource_type": "AWSAccount"}}
}

test_rule7_fail_when_explicitly_disabled if {
	acct := {"resource_type": "AWSAccount", "cloudtrail_enabled": false, "guardduty_enabled": false}
	count(rule7_detection.deny) == 2 with input as {"resource": acct}
}

# ---- row 9: Rule 8 lifecycle
test_rule8_pass if {
	count(rule8_lifecycle.deny) == 0 with input as {"resource": good_bucket}
}

test_rule8_fail if {
	bad := object.union(good_bucket, {"has_lifecycle_expiration": false})
	count(rule8_lifecycle.deny) == 1 with input as {"resource": bad}
}

# ---- row 10: Rule 15 visibility flag (warn, never deny)
test_rule15_no_warning_inside_approved_regions if {
	res := {"personal_data": true, "region": "ap-south-1", "approved_regions": ["ap-south-1", "ap-south-2"]}
	count(rule15_region.warn) == 0 with input as {"resource": res}
}

test_rule15_warns_outside_approved_regions if {
	res := {"personal_data": true, "region": "us-east-1", "approved_regions": ["ap-south-1", "ap-south-2"]}
	count(rule15_region.warn) == 1 with input as {"resource": res}
}

test_rule15_silent_without_approved_list if {
	res := {"personal_data": true, "region": "us-east-1", "approved_regions": []}
	count(rule15_region.warn) == 0 with input as {"resource": res}
}

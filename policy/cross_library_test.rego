package argus.cross_library_test

import data.argus.dpdp.rule6_public
import data.argus.dpdp.rule6_versioning
import data.argus.dpdp.rule6a
import data.argus.generic.s3_default_encryption
import data.argus.generic.s3_public_access_block
import rego.v1

# The Phase 4 demonstration case: a patch that closes the public bucket (generic hygiene is satisfied)
# but leaves versioning suspended (the DPDP library still fails it).
patched_bucket := {
	"resource_type": "AWSS3Bucket",
	"personal_data": true,
	"default_encryption": true,
	"encryption_algorithm": "aws:kms",
	"versioning_status": "Suspended",
	"block_public_acls": true,
	"block_public_policy": true,
	"ignore_public_acls": true,
	"restrict_public_buckets": true,
}

test_generic_pass_dpdp_fail if {
	count(s3_public_access_block.deny) == 0 with input as {"resource": patched_bucket}
	count(s3_default_encryption.deny) == 0 with input as {"resource": patched_bucket}
	count(rule6_public.deny) == 0 with input as {"resource": patched_bucket}
	count(rule6a.deny) == 0 with input as {"resource": patched_bucket}
	count(rule6_versioning.deny) == 1 with input as {"resource": patched_bucket}
}

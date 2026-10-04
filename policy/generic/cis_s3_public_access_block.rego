# rule_id: cis.s3_public_access_block
# title: S3 bucket must block all four kinds of public access
# source: CIS-style generic hygiene
package argus.generic.s3_public_access_block

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.block_public_acls == true
	msg := {"rule_id": "cis.s3_public_access_block", "reason": "block_public_acls is not enabled"}
}

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.block_public_policy == true
	msg := {"rule_id": "cis.s3_public_access_block", "reason": "block_public_policy is not enabled"}
}

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.ignore_public_acls == true
	msg := {"rule_id": "cis.s3_public_access_block", "reason": "ignore_public_acls is not enabled"}
}

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.restrict_public_buckets == true
	msg := {"rule_id": "cis.s3_public_access_block", "reason": "restrict_public_buckets is not enabled"}
}

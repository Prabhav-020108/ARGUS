# rule_id: dpdp.rule6_public_exposure
# dpdp_rule: Rule 6 - public exposure
# mapping_row: 6
# title: S3 bucket must not allow public access
package argus.dpdp.rule6_public

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.block_public_acls == true
	msg := {"rule_id": "dpdp.rule6_public_exposure", "reason": "block_public_acls is not enabled"}
}

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.block_public_policy == true
	msg := {"rule_id": "dpdp.rule6_public_exposure", "reason": "block_public_policy is not enabled"}
}

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.ignore_public_acls == true
	msg := {"rule_id": "dpdp.rule6_public_exposure", "reason": "ignore_public_acls is not enabled"}
}

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.restrict_public_buckets == true
	msg := {"rule_id": "dpdp.rule6_public_exposure", "reason": "restrict_public_buckets is not enabled"}
}

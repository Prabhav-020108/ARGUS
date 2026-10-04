# rule_id: dpdp.rule6_versioning
# dpdp_rule: Rule 6 - recoverability
# mapping_row: 5
# title: S3 buckets holding personal data must have versioning enabled
# note: Cartography omits versioning_status for never-versioned buckets, so a missing value also denies
package argus.dpdp.rule6_versioning

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	input.resource.personal_data == true
	not input.resource.versioning_status == "Enabled"
	msg := {"rule_id": "dpdp.rule6_versioning", "reason": "versioning is not enabled on a bucket holding personal data"}
}

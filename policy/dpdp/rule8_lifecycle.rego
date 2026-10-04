# rule_id: dpdp.rule8_lifecycle
# dpdp_rule: Rule 8 - retention and erasure
# mapping_row: 9
# title: S3 buckets holding personal data must have a lifecycle expiration rule
# note: has_lifecycle_expiration is a derived boolean supplied by the finding builder (UNVERIFIED in Cartography)
package argus.dpdp.rule8_lifecycle

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	input.resource.personal_data == true
	not input.resource.has_lifecycle_expiration == true
	msg := {"rule_id": "dpdp.rule8_lifecycle", "reason": "no lifecycle expiration rule on a bucket holding personal data"}
}

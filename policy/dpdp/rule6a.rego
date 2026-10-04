# rule_id: dpdp.rule6a
# dpdp_rule: Rule 6(1)(a) - encryption
# mapping_row: 1
# title: S3 bucket must have server-side encryption enabled
package argus.dpdp.rule6a

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.default_encryption == true
	msg := {"rule_id": "dpdp.rule6a", "reason": "S3 default encryption is not enabled"}
}

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	input.resource.default_encryption == true
	not input.resource.encryption_algorithm in {"AES256", "aws:kms", "aws:kms:dsse"}
	msg := {"rule_id": "dpdp.rule6a", "reason": "S3 encryption algorithm is not an approved algorithm"}
}

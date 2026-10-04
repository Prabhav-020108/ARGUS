# rule_id: dpdp.rule6_logging
# dpdp_rule: Rule 6 - logging and auditability
# mapping_row: 7
# title: S3 buckets must have access logging enabled
package argus.dpdp.rule6_logging

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.logging_enabled == true
	msg := {"rule_id": "dpdp.rule6_logging", "reason": "S3 access logging is not enabled"}
}

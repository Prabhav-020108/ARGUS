# rule_id: dpdp.rule6a_rds
# dpdp_rule: Rule 6(1)(a) - encryption at rest
# mapping_row: 2
# title: RDS instance must have storage encryption enabled (UNVERIFIED: no RDS synced yet)
package argus.dpdp.rule6a_rds

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSRDSInstance"
	not input.resource.storage_encrypted == true
	msg := {"rule_id": "dpdp.rule6a_rds", "reason": "RDS storage encryption is not enabled"}
}

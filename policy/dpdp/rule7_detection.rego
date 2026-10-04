# rule_id: dpdp.rule7_detection
# dpdp_rule: Rule 7 - 72-hour breach notification readiness
# mapping_row: 8
# title: CloudTrail and GuardDuty must not be explicitly disabled
# note: NOT YET INGESTIBLE (cartography.json does not sync cloudtrail/guardduty). Deny only fires when the
#       derived boolean is explicitly false, so missing data never raises a false alarm.
package argus.dpdp.rule7_detection

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSAccount"
	input.resource.cloudtrail_enabled == false
	msg := {"rule_id": "dpdp.rule7_detection", "reason": "CloudTrail is disabled"}
}

deny contains msg if {
	input.resource.resource_type == "AWSAccount"
	input.resource.guardduty_enabled == false
	msg := {"rule_id": "dpdp.rule7_detection", "reason": "GuardDuty is disabled"}
}

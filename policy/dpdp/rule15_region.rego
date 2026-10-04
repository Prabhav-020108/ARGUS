# rule_id: dpdp.rule15_region
# dpdp_rule: Rule 15 - cross-border transfer
# mapping_row: 10
# title: Flag (never hard-fail) personal-data resources outside the approved regions
# note: Rule 15 is permissive, so this rule produces a visibility WARNING, not a deny.
package argus.dpdp.rule15_region

import rego.v1

warn contains msg if {
	input.resource.personal_data == true
	count(input.resource.approved_regions) > 0
	not input.resource.region in input.resource.approved_regions
	msg := {"rule_id": "dpdp.rule15_region", "reason": "personal-data resource is outside the approved regions (visibility flag only)"}
}

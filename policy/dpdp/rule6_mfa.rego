# rule_id: dpdp.rule6_account_mfa
# dpdp_rule: Rule 6 - access control (MFA)
# mapping_row: 4
# title: Account-level MFA must be enabled
package argus.dpdp.rule6_mfa

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSAccount"
	not input.resource.account_mfa_enabled == true
	msg := {"rule_id": "dpdp.rule6_account_mfa", "reason": "account-level MFA is not enabled"}
}

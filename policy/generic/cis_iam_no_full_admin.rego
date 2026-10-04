# rule_id: cis.iam_no_full_admin
# title: IAM policy statement must not allow all actions on all resources
# source: CIS-style generic hygiene
package argus.generic.iam_no_full_admin

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSPolicyStatement"
	input.resource.effect == "Allow"
	"*" in input.resource.action
	"*" in input.resource.resource
	msg := {"rule_id": "cis.iam_no_full_admin", "reason": "statement allows all actions on all resources"}
}

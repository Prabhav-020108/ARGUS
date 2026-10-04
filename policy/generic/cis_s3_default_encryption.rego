# rule_id: cis.s3_default_encryption
# title: S3 bucket must have default server-side encryption enabled
# source: CIS-style generic hygiene
package argus.generic.s3_default_encryption

import rego.v1

deny contains msg if {
	input.resource.resource_type == "AWSS3Bucket"
	not input.resource.default_encryption == true
	msg := {"rule_id": "cis.s3_default_encryption", "reason": "default encryption is not enabled"}
}

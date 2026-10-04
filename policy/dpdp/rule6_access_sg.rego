# rule_id: dpdp.rule6_sg_open_ingress
# dpdp_rule: Rule 6 - access control
# mapping_row: 3
# title: Security group must not allow world-open inbound access on all ports or sensitive ports
package argus.dpdp.rule6_access_sg

import rego.v1

sensitive_ports := {22, 3389, 3306, 5432, 1433, 27017, 6379}

world_open if {
	input.resource.ip_range in {"0.0.0.0/0", "::/0"}
}

deny contains msg if {
	input.resource.resource_type == "AWSIpPermissionInbound"
	world_open
	input.resource.protocol == "-1"
	msg := {"rule_id": "dpdp.rule6_sg_open_ingress", "reason": "world-open inbound rule allows all traffic"}
}

deny contains msg if {
	input.resource.resource_type == "AWSIpPermissionInbound"
	world_open
	some port in sensitive_ports
	input.resource.fromport <= port
	port <= input.resource.toport
	msg := {"rule_id": "dpdp.rule6_sg_open_ingress", "reason": sprintf("world-open inbound rule exposes sensitive port %d", [port])}
}

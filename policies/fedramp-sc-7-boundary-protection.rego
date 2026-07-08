package concord.fedramp.sc_7

import rego.v1

# NIST 800-53 Rev 5 SC-7 (Boundary Protection) / FedRAMP Moderate — the system
# must monitor and control communications at the external boundary and at key
# internal boundaries, denying traffic by default. This control inspects every
# AWS security group and, for those protecting a private- or restricted-tier
# resource, confirms that no ingress rule permits direct access from an
# untrusted network (0.0.0.0/0 or ::/0).
#
# Reused from concord-controlpack-pci-dss r_1_3_1 (perimeter firewall).
# Evidence: input.security_groups.groups.

protected_tiers := {"private", "restricted"}

untrusted_cidr("0.0.0.0/0")

untrusted_cidr("::/0")

deny contains msg if {
	not input.security_groups
	msg := "SC-7: no security-group evidence collected"
}

deny contains msg if {
	some sg in input.security_groups.groups
	sg.scope in protected_tiers
	some rule in sg.ingress_rules
	untrusted_cidr(rule.cidr)
	msg := sprintf("SC-7: security group %q protects a %s-tier resource but permits direct inbound from the untrusted network %q; the authorization boundary must deny all direct Internet access to internal resources (NIST 800-53 SC-7 / FedRAMP Moderate)", [sg.id, sg.scope, rule.cidr])
}

# Fail closed: a security group whose protected tier is not declared cannot be
# shown to sit on the trusted side of the boundary.
deny contains msg if {
	some sg in input.security_groups.groups
	not sg.scope
	msg := sprintf("SC-7: security group %q does not declare the network tier it protects; every group must be classified so internal tiers can be confirmed isolated from untrusted networks (NIST 800-53 SC-7 / FedRAMP Moderate)", [sg.id])
}

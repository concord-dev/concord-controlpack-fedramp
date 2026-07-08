package concord.fedramp.remote_access

import rego.v1

# NIST SP 800-53 Rev 5 AC-17 (Remote Access) / FedRAMP Moderate.
# Remote access must be authorized, routed through managed access points, and
# protected with cryptography (AC-17(2)); it must never be reachable directly
# from an untrusted network. Concord inspects every security group and fails
# any ingress rule that exposes a remote-administration port (SSH 22, RDP 3389)
# to the Internet (0.0.0.0/0 or ::/0), and any rule marked as remote
# administrative access that is not confirmed to be encrypted.
# Evidence: input.security_groups.groups[].ingress_rules[].

# Ports that carry interactive remote administration.
remote_admin_ports := {22: "SSH", 3389: "RDP"}

untrusted_cidr("0.0.0.0/0")

untrusted_cidr("::/0")

# Fail closed: without security-group evidence remote access is unproven.
deny contains msg if {
	not input.security_groups
	msg := "no security-group evidence collected — cannot verify remote-access restrictions (NIST 800-53 AC-17 / FedRAMP Moderate)"
}

# Remote-administration port reachable directly from an untrusted network.
deny contains msg if {
	some sg in input.security_groups.groups
	some rule in sg.ingress_rules
	some port, name in remote_admin_ports
	port_in_range(port, rule)
	untrusted_cidr(rule.cidr)
	msg := sprintf("security group %q exposes remote administration via %s (port %d) to the untrusted network %q — remote access must be restricted to authorized, managed sources (NIST 800-53 AC-17 / FedRAMP Moderate)", [sg.id, name, port, rule.cidr])
}

# Fail closed: a rule flagged as administrative that does not affirm encryption
# (catches, for example, RDP or web administration exposed without TLS).
deny contains msg if {
	some sg in input.security_groups.groups
	some rule in sg.ingress_rules
	rule.admin == true
	not rule.encrypted == true
	msg := sprintf("security group %q permits remote administrative access on ports %d-%d that is not confirmed to use encryption — remote access must use cryptographic protection (NIST 800-53 AC-17(2) / FedRAMP Moderate)", [sg.id, rule.from_port, rule.to_port])
}

port_in_range(port, rule) if {
	rule.from_port <= port
	rule.to_port >= port
}

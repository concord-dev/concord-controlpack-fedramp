package concord.fedramp.cm_7_least_functionality

import rego.v1

# NIST 800-53 Rev 5 CM-7 / CM-7(1) / FedRAMP Moderate — Least Functionality:
# the system must provide only essential capabilities and disable unnecessary
# or insecure functions, ports, protocols, and services. Evidence: AWS security
# groups (input.security_groups.groups[]). Adapted from PCI DSS 2.2.5
# (concord.pci_dss.r_2_2_5). Any ingress rule that permits a known
# unnecessary/insecure service, or that opens all ports, denies. Fail-closed:
# absent evidence denies.

# Ports carrying services that are almost never essential and are commonly
# insecure; an open ingress rule for one indicates least functionality has not
# been applied.
unnecessary_services := {
	21: "FTP",
	23: "Telnet",
	25: "SMTP",
	69: "TFTP",
	111: "Sun RPC / portmapper",
	135: "MS-RPC",
	137: "NetBIOS name service",
	138: "NetBIOS datagram service",
	139: "NetBIOS session service",
	445: "SMB / CIFS",
	512: "rexec",
	513: "rlogin",
	514: "rsh",
	873: "rsync",
	2049: "NFS",
	5900: "VNC",
	6000: "X11",
}

# Fail closed: no security-group evidence means hardening cannot be shown.
deny contains msg if {
	not input.security_groups
	msg := "no security-group evidence collected — cannot demonstrate least functionality (NIST 800-53 CM-7 / FedRAMP Moderate)"
}

deny contains msg if {
	some sg in input.security_groups.groups
	some rule in sg.ingress_rules
	some port, name in unnecessary_services
	port_in_range(port, rule)
	msg := sprintf("security group %q permits %s (port %d) from %q — this unnecessary/insecure service must be disabled (NIST 800-53 CM-7 / FedRAMP Moderate)", [sg.id, name, port, rule.cidr])
}

# Fail closed: a rule opening all ports/protocols exposes every unnecessary
# service even without an explicit port bound.
deny contains msg if {
	some sg in input.security_groups.groups
	some rule in sg.ingress_rules
	opens_all_ports(rule)
	msg := sprintf("security group %q permits all ports and protocols inbound from %q, necessarily exposing unnecessary and insecure services (NIST 800-53 CM-7 / FedRAMP Moderate)", [sg.id, rule.cidr])
}

port_in_range(port, rule) if {
	rule.from_port <= port
	rule.to_port >= port
}

opens_all_ports(rule) if rule.protocol == "-1"

opens_all_ports(rule) if rule.protocol == "all"

opens_all_ports(rule) if {
	not is_number(rule.from_port)
	not is_number(rule.to_port)
}

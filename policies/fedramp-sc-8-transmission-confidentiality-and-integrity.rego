package concord.fedramp.sc_8

import rego.v1

# NIST 800-53 Rev 5 SC-8 (Transmission Confidentiality and Integrity) with
# SC-8(1) cryptographic protection / FedRAMP Moderate — information transmitted
# across the authorization boundary must be protected with TLS 1.2 or higher.
# Every S3 bucket must deny non-TLS requests; every load-balancer listener must
# speak HTTPS/TLS with a security policy whose minimum protocol is TLS 1.2.
#
# Reused from concord-controlpack-hipaa encryption_in_transit
# (§164.312(e)(2)(ii)). Evidence: input.tls_endpoints.{buckets,load_balancers}.

# ELB security policies whose minimum negotiated protocol is TLS 1.2 or 1.3.
tls12plus_policies := {
	"ELBSecurityPolicy-TLS13-1-2-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
	"ELBSecurityPolicy-TLS-1-2-2017-01",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
	"ELBSecurityPolicy-FS-1-2-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2020-10",
}

deny contains msg if {
	not input.tls_endpoints
	msg := "SC-8: no transmission-endpoint evidence collected"
}

# S3 bucket that does not deny non-TLS requests.
deny contains msg if {
	some b in input.tls_endpoints.buckets
	not bucket_enforces_tls(b)
	msg := sprintf("SC-8: S3 bucket %q does not deny non-TLS requests (missing aws:SecureTransport=false deny); transmitted information must be TLS-protected (NIST 800-53 SC-8 / FedRAMP Moderate)", [b.name])
}

# Load-balancer listener carrying traffic over a plaintext protocol.
deny contains msg if {
	some lb in input.tls_endpoints.load_balancers
	some l in lb.listeners
	plaintext_protocol(l)
	msg := sprintf("SC-8: load balancer %q has a %s listener on port %d that transmits information without TLS (NIST 800-53 SC-8 / FedRAMP Moderate)", [lb.name, upper(l.protocol), l.port])
}

# Load-balancer listener whose TLS policy permits protocols below TLS 1.2.
deny contains msg if {
	some lb in input.tls_endpoints.load_balancers
	some l in lb.listeners
	encrypted_protocol(l)
	not tls12plus(l)
	msg := sprintf("SC-8: load balancer %q listener on port %d uses SSL policy %q which permits TLS below 1.2 (NIST 800-53 SC-8(1) / FedRAMP Moderate)", [lb.name, l.port, object.get(l, "ssl_policy", "<none>")])
}

bucket_enforces_tls(b) if {
	some stmt in b.policy.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
	action_covers_all(stmt)
}

action_covers_all(stmt) if {
	stmt.Action == "s3:*"
}

action_covers_all(stmt) if {
	some a in stmt.Action
	a == "s3:*"
}

plaintext_protocol(l) if {
	upper(l.protocol) == "HTTP"
}

plaintext_protocol(l) if {
	upper(l.protocol) == "TCP"
}

encrypted_protocol(l) if {
	upper(l.protocol) == "HTTPS"
}

encrypted_protocol(l) if {
	upper(l.protocol) == "TLS"
}

tls12plus(l) if {
	tls12plus_policies[l.ssl_policy]
}

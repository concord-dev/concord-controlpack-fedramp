package concord.fedramp.au_12

import rego.v1

# NIST 800-53 AU-12 (Audit Record Generation) / FedRAMP Moderate — the system
# must provide audit-record generation capability for the defined auditable
# events at all in-scope components, account-wide. Concord verifies that AWS
# CloudTrail is configured with at least one multi-region trail that is actively
# logging, so that every region and component generates audit records. Fail
# closed when no qualifying trail is present.

trails := input.audit_trail.cloudtrail.trails

deny contains msg if {
	not input.audit_trail
	msg := "no audit-trail evidence collected"
}

deny contains msg if {
	input.audit_trail
	count(trails) == 0
	msg := "no CloudTrail trail is configured; the system generates no account-wide audit records (NIST 800-53 AU-12 / FedRAMP Moderate)"
}

deny contains msg if {
	input.audit_trail
	count(trails) > 0
	not has_multi_region_logging_trail
	msg := "no multi-region CloudTrail trail is both enabled and logging; audit-record generation does not cover every region (NIST 800-53 AU-12 / FedRAMP Moderate)"
}

deny contains msg if {
	some trail in trails
	trail.is_multi_region_trail
	not trail.is_logging
	msg := sprintf("multi-region CloudTrail trail %q is not currently logging; audit-record generation is halted (NIST 800-53 AU-12 / FedRAMP Moderate)", [trail.name])
}

has_multi_region_logging_trail if {
	some trail in trails
	trail.is_multi_region_trail
	trail.is_logging
}

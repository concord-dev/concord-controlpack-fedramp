package concord.fedramp.au_4

import rego.v1

# NIST 800-53 AU-4 (Audit Log Storage Capacity) / FedRAMP Moderate — the system
# must allocate audit log storage capacity sufficient to retain records for the
# organisation-defined period and reduce the likelihood of exceeding capacity.
# Concord verifies that every audit-log CloudWatch log group reserves at least
# the organisation-defined minimum retention and that any S3 lifecycle rule used
# for overflow storage does not expire records earlier than that floor. Fail
# closed when no storage-capacity mechanism exists.

min_retention_days := 90

deny contains msg if {
	not input.audit_retention
	msg := "no audit-log storage-capacity evidence collected"
}

deny contains msg if {
	input.audit_retention
	not has_capacity_mechanism
	msg := "no audit-log storage capacity is allocated (neither CloudWatch log-group retention nor an S3 lifecycle rule); failing closed (NIST 800-53 AU-4 / FedRAMP Moderate)"
}

deny contains msg if {
	some g in input.audit_retention.log_groups
	g.is_audit_log
	g.retention_in_days < min_retention_days
	msg := sprintf("audit log group %q reserves only %d days of retention, below the organisation-defined minimum of %d days (NIST 800-53 AU-4 / FedRAMP Moderate)", [g.name, g.retention_in_days, min_retention_days])
}

deny contains msg if {
	lc := input.audit_retention.s3_lifecycle
	lc.expiration_days < min_retention_days
	msg := sprintf("S3 audit-log archive bucket %q expires objects after %d days, below the organisation-defined minimum of %d days (NIST 800-53 AU-4 / FedRAMP Moderate)", [lc.bucket, lc.expiration_days, min_retention_days])
}

has_capacity_mechanism if {
	count(input.audit_retention.log_groups) > 0
}

has_capacity_mechanism if {
	input.audit_retention.s3_lifecycle
}

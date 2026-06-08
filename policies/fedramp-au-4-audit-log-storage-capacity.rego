package concord.fedramp.fedramp_au_4_audit_log_storage_capacity

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_au_4_audit_log_storage_capacity")
	msg := "FEDRAMP-AU-4-audit-log-storage-capacity: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_au_4_audit_log_storage_capacity.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AU-4-audit-log-storage-capacity: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

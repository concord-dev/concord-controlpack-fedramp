package concord.fedramp.fedramp_au_3_content_of_audit_records

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_au_3_content_of_audit_records")
	msg := "FEDRAMP-AU-3-content-of-audit-records: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_au_3_content_of_audit_records.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AU-3-content-of-audit-records: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

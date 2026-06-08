package concord.fedramp.fedramp_au_12_audit_generation

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_au_12_audit_generation")
	msg := "FEDRAMP-AU-12-audit-generation: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_au_12_audit_generation.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AU-12-audit-generation: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

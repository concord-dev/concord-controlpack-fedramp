package concord.fedramp.fedramp_au_9_protection_of_audit_information

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_au_9_protection_of_audit_information")
	msg := "FEDRAMP-AU-9-protection-of-audit-information: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_au_9_protection_of_audit_information.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AU-9-protection-of-audit-information: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

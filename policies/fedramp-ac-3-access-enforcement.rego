package concord.fedramp.fedramp_ac_3_access_enforcement

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ac_3_access_enforcement")
	msg := "FEDRAMP-AC-3-access-enforcement: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ac_3_access_enforcement.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AC-3-access-enforcement: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

package concord.fedramp.fedramp_ac_4_information_flow_enforcement

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ac_4_information_flow_enforcement")
	msg := "FEDRAMP-AC-4-information-flow-enforcement: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ac_4_information_flow_enforcement.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AC-4-information-flow-enforcement: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

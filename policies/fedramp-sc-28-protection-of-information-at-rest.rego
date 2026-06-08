package concord.fedramp.fedramp_sc_28_protection_of_information_at_rest

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_sc_28_protection_of_information_at_rest")
	msg := "FEDRAMP-SC-28-protection-of-information-at-rest: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_sc_28_protection_of_information_at_rest.resources
	not r.compliant
	msg := sprintf("FEDRAMP-SC-28-protection-of-information-at-rest: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

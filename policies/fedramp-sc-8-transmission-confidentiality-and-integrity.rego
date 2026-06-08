package concord.fedramp.fedramp_sc_8_transmission_confidentiality_and_integrity

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_sc_8_transmission_confidentiality_and_integrity")
	msg := "FEDRAMP-SC-8-transmission-confidentiality-and-integrity: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_sc_8_transmission_confidentiality_and_integrity.resources
	not r.compliant
	msg := sprintf("FEDRAMP-SC-8-transmission-confidentiality-and-integrity: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

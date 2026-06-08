package concord.fedramp.fedramp_sc_7_boundary_protection

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_sc_7_boundary_protection")
	msg := "FEDRAMP-SC-7-boundary-protection: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_sc_7_boundary_protection.resources
	not r.compliant
	msg := sprintf("FEDRAMP-SC-7-boundary-protection: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

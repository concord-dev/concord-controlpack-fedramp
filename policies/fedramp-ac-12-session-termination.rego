package concord.fedramp.fedramp_ac_12_session_termination

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ac_12_session_termination")
	msg := "FEDRAMP-AC-12-session-termination: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ac_12_session_termination.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AC-12-session-termination: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

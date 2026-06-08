package concord.fedramp.fedramp_ac_7_unsuccessful_logon_attempts

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ac_7_unsuccessful_logon_attempts")
	msg := "FEDRAMP-AC-7-unsuccessful-logon-attempts: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ac_7_unsuccessful_logon_attempts.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AC-7-unsuccessful-logon-attempts: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

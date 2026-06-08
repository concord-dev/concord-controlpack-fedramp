package concord.fedramp.fedramp_ac_6_least_privilege

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ac_6_least_privilege")
	msg := "FEDRAMP-AC-6-least-privilege: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ac_6_least_privilege.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AC-6-least-privilege: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

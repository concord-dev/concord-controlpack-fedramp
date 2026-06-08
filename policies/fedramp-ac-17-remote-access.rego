package concord.fedramp.fedramp_ac_17_remote_access

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ac_17_remote_access")
	msg := "FEDRAMP-AC-17-remote-access: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ac_17_remote_access.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AC-17-remote-access: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

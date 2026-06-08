package concord.fedramp.fedramp_ia_2_1_mfa_privileged

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ia_2_1_mfa_privileged")
	msg := "FEDRAMP-IA-2-1-mfa-privileged: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ia_2_1_mfa_privileged.resources
	not r.compliant
	msg := sprintf("FEDRAMP-IA-2-1-mfa-privileged: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

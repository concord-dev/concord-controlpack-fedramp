package concord.fedramp.fedramp_ia_2_2_mfa_non_privileged

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ia_2_2_mfa_non_privileged")
	msg := "FEDRAMP-IA-2-2-mfa-non-privileged: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ia_2_2_mfa_non_privileged.resources
	not r.compliant
	msg := sprintf("FEDRAMP-IA-2-2-mfa-non-privileged: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

package concord.fedramp.fedramp_si_2_flaw_remediation

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_si_2_flaw_remediation")
	msg := "FEDRAMP-SI-2-flaw-remediation: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_si_2_flaw_remediation.resources
	not r.compliant
	msg := sprintf("FEDRAMP-SI-2-flaw-remediation: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

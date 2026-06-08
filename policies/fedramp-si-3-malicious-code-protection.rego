package concord.fedramp.fedramp_si_3_malicious_code_protection

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_si_3_malicious_code_protection")
	msg := "FEDRAMP-SI-3-malicious-code-protection: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_si_3_malicious_code_protection.resources
	not r.compliant
	msg := sprintf("FEDRAMP-SI-3-malicious-code-protection: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

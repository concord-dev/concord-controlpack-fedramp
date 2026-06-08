package concord.fedramp.fedramp_sc_13_cryptographic_protection

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_sc_13_cryptographic_protection")
	msg := "FEDRAMP-SC-13-cryptographic-protection: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_sc_13_cryptographic_protection.resources
	not r.compliant
	msg := sprintf("FEDRAMP-SC-13-cryptographic-protection: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

package concord.fedramp.fedramp_ia_2_identification_and_authentication

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ia_2_identification_and_authentication")
	msg := "FEDRAMP-IA-2-identification-and-authentication: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ia_2_identification_and_authentication.resources
	not r.compliant
	msg := sprintf("FEDRAMP-IA-2-identification-and-authentication: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

package concord.fedramp.fedramp_ia_5_authenticator_management

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ia_5_authenticator_management")
	msg := "FEDRAMP-IA-5-authenticator-management: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ia_5_authenticator_management.resources
	not r.compliant
	msg := sprintf("FEDRAMP-IA-5-authenticator-management: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

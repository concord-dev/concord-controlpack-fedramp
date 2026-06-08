package concord.fedramp.fedramp_ac_2_account_management

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ac_2_account_management")
	msg := "FEDRAMP-AC-2-account-management: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_ac_2_account_management.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AC-2-account-management: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

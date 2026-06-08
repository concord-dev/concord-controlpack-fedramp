package concord.fedramp.fedramp_cm_7_least_functionality

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_cm_7_least_functionality")
	msg := "FEDRAMP-CM-7-least-functionality: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_cm_7_least_functionality.resources
	not r.compliant
	msg := sprintf("FEDRAMP-CM-7-least-functionality: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

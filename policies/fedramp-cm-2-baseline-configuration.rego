package concord.fedramp.fedramp_cm_2_baseline_configuration

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_cm_2_baseline_configuration")
	msg := "FEDRAMP-CM-2-baseline-configuration: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_cm_2_baseline_configuration.resources
	not r.compliant
	msg := sprintf("FEDRAMP-CM-2-baseline-configuration: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

package concord.fedramp.fedramp_si_4_system_monitoring

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_si_4_system_monitoring")
	msg := "FEDRAMP-SI-4-system-monitoring: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_si_4_system_monitoring.resources
	not r.compliant
	msg := sprintf("FEDRAMP-SI-4-system-monitoring: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

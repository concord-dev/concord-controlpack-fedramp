package concord.fedramp.fedramp_au_2_event_logging

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_au_2_event_logging")
	msg := "FEDRAMP-AU-2-event-logging: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_au_2_event_logging.resources
	not r.compliant
	msg := sprintf("FEDRAMP-AU-2-event-logging: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

package concord.fedramp.fedramp_cm_6_configuration_settings

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_cm_6_configuration_settings")
	msg := "FEDRAMP-CM-6-configuration-settings: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_cm_6_configuration_settings.resources
	not r.compliant
	msg := sprintf("FEDRAMP-CM-6-configuration-settings: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

package concord.fedramp.fedramp_si_7_software_firmware_information_integrity

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_si_7_software_firmware_information_integrity")
	msg := "FEDRAMP-SI-7-software-firmware-information-integrity: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_si_7_software_firmware_information_integrity.resources
	not r.compliant
	msg := sprintf("FEDRAMP-SI-7-software-firmware-information-integrity: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

package concord.fedramp.fedramp_cm_3_configuration_change_control

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_cm_3_configuration_change_control")
	msg := "FEDRAMP-CM-3-configuration-change-control: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_cm_3_configuration_change_control)
	msg := sprintf("FEDRAMP-CM-3-configuration-change-control: attestation expired (expires_at=%s)", [input.fedramp_cm_3_configuration_change_control.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_cm_3_configuration_change_control, 365)
	msg := sprintf("FEDRAMP-CM-3-configuration-change-control: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_cm_3_configuration_change_control.last_review_at])
}

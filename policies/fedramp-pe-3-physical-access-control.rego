package concord.fedramp.fedramp_pe_3_physical_access_control

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_pe_3_physical_access_control")
	msg := "FEDRAMP-PE-3-physical-access-control: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_pe_3_physical_access_control)
	msg := sprintf("FEDRAMP-PE-3-physical-access-control: attestation expired (expires_at=%s)", [input.fedramp_pe_3_physical_access_control.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_pe_3_physical_access_control, 365)
	msg := sprintf("FEDRAMP-PE-3-physical-access-control: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_pe_3_physical_access_control.last_review_at])
}

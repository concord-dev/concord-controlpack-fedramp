package concord.fedramp.fedramp_ps_4_personnel_termination

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ps_4_personnel_termination")
	msg := "FEDRAMP-PS-4-personnel-termination: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_ps_4_personnel_termination)
	msg := sprintf("FEDRAMP-PS-4-personnel-termination: attestation expired (expires_at=%s)", [input.fedramp_ps_4_personnel_termination.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_ps_4_personnel_termination, 365)
	msg := sprintf("FEDRAMP-PS-4-personnel-termination: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_ps_4_personnel_termination.last_review_at])
}

package concord.fedramp.fedramp_ps_3_personnel_screening

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ps_3_personnel_screening")
	msg := "FEDRAMP-PS-3-personnel-screening: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_ps_3_personnel_screening)
	msg := sprintf("FEDRAMP-PS-3-personnel-screening: attestation expired (expires_at=%s)", [input.fedramp_ps_3_personnel_screening.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_ps_3_personnel_screening, 365)
	msg := sprintf("FEDRAMP-PS-3-personnel-screening: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_ps_3_personnel_screening.last_review_at])
}

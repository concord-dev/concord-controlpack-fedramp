package concord.fedramp.fedramp_ac_5_separation_of_duties

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ac_5_separation_of_duties")
	msg := "FEDRAMP-AC-5-separation-of-duties: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_ac_5_separation_of_duties)
	msg := sprintf("FEDRAMP-AC-5-separation-of-duties: attestation expired (expires_at=%s)", [input.fedramp_ac_5_separation_of_duties.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_ac_5_separation_of_duties, 365)
	msg := sprintf("FEDRAMP-AC-5-separation-of-duties: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_ac_5_separation_of_duties.last_review_at])
}

package concord.fedramp.fedramp_mp_6_media_sanitisation

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_mp_6_media_sanitisation")
	msg := "FEDRAMP-MP-6-media-sanitisation: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_mp_6_media_sanitisation)
	msg := sprintf("FEDRAMP-MP-6-media-sanitisation: attestation expired (expires_at=%s)", [input.fedramp_mp_6_media_sanitisation.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_mp_6_media_sanitisation, 365)
	msg := sprintf("FEDRAMP-MP-6-media-sanitisation: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_mp_6_media_sanitisation.last_review_at])
}

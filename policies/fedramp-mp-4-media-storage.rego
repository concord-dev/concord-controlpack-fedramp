package concord.fedramp.fedramp_mp_4_media_storage

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_mp_4_media_storage")
	msg := "FEDRAMP-MP-4-media-storage: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_mp_4_media_storage)
	msg := sprintf("FEDRAMP-MP-4-media-storage: attestation expired (expires_at=%s)", [input.fedramp_mp_4_media_storage.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_mp_4_media_storage, 365)
	msg := sprintf("FEDRAMP-MP-4-media-storage: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_mp_4_media_storage.last_review_at])
}

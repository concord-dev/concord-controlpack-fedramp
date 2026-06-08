package concord.fedramp.fedramp_ac_11_session_lock

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ac_11_session_lock")
	msg := "FEDRAMP-AC-11-session-lock: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_ac_11_session_lock)
	msg := sprintf("FEDRAMP-AC-11-session-lock: attestation expired (expires_at=%s)", [input.fedramp_ac_11_session_lock.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_ac_11_session_lock, 365)
	msg := sprintf("FEDRAMP-AC-11-session-lock: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_ac_11_session_lock.last_review_at])
}

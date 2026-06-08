package concord.fedramp.fedramp_ir_4_incident_handling

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ir_4_incident_handling")
	msg := "FEDRAMP-IR-4-incident-handling: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_ir_4_incident_handling)
	msg := sprintf("FEDRAMP-IR-4-incident-handling: attestation expired (expires_at=%s)", [input.fedramp_ir_4_incident_handling.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_ir_4_incident_handling, 365)
	msg := sprintf("FEDRAMP-IR-4-incident-handling: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_ir_4_incident_handling.last_review_at])
}

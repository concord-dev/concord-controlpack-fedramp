package concord.fedramp.fedramp_ir_6_incident_reporting

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ir_6_incident_reporting")
	msg := "FEDRAMP-IR-6-incident-reporting: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_ir_6_incident_reporting)
	msg := sprintf("FEDRAMP-IR-6-incident-reporting: attestation expired (expires_at=%s)", [input.fedramp_ir_6_incident_reporting.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_ir_6_incident_reporting, 365)
	msg := sprintf("FEDRAMP-IR-6-incident-reporting: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_ir_6_incident_reporting.last_review_at])
}

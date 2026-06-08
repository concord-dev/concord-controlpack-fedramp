package concord.fedramp.fedramp_ca_2_control_assessments

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ca_2_control_assessments")
	msg := "FEDRAMP-CA-2-control-assessments: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_ca_2_control_assessments)
	msg := sprintf("FEDRAMP-CA-2-control-assessments: attestation expired (expires_at=%s)", [input.fedramp_ca_2_control_assessments.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_ca_2_control_assessments, 365)
	msg := sprintf("FEDRAMP-CA-2-control-assessments: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_ca_2_control_assessments.last_review_at])
}

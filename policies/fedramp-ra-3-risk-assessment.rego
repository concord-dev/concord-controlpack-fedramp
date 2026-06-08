package concord.fedramp.fedramp_ra_3_risk_assessment

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ra_3_risk_assessment")
	msg := "FEDRAMP-RA-3-risk-assessment: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_ra_3_risk_assessment)
	msg := sprintf("FEDRAMP-RA-3-risk-assessment: attestation expired (expires_at=%s)", [input.fedramp_ra_3_risk_assessment.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_ra_3_risk_assessment, 365)
	msg := sprintf("FEDRAMP-RA-3-risk-assessment: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_ra_3_risk_assessment.last_review_at])
}

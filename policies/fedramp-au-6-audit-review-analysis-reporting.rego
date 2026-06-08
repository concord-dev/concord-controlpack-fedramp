package concord.fedramp.fedramp_au_6_audit_review_analysis_reporting

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_au_6_audit_review_analysis_reporting")
	msg := "FEDRAMP-AU-6-audit-review-analysis-reporting: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_au_6_audit_review_analysis_reporting)
	msg := sprintf("FEDRAMP-AU-6-audit-review-analysis-reporting: attestation expired (expires_at=%s)", [input.fedramp_au_6_audit_review_analysis_reporting.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_au_6_audit_review_analysis_reporting, 365)
	msg := sprintf("FEDRAMP-AU-6-audit-review-analysis-reporting: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_au_6_audit_review_analysis_reporting.last_review_at])
}

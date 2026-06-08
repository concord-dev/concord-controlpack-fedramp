package concord.fedramp.fedramp_cp_2_contingency_plan

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_cp_2_contingency_plan")
	msg := "FEDRAMP-CP-2-contingency-plan: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_cp_2_contingency_plan)
	msg := sprintf("FEDRAMP-CP-2-contingency-plan: attestation expired (expires_at=%s)", [input.fedramp_cp_2_contingency_plan.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_cp_2_contingency_plan, 365)
	msg := sprintf("FEDRAMP-CP-2-contingency-plan: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_cp_2_contingency_plan.last_review_at])
}

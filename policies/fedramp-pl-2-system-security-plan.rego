package concord.fedramp.fedramp_pl_2_system_security_plan

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_pl_2_system_security_plan")
	msg := "FEDRAMP-PL-2-system-security-plan: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_pl_2_system_security_plan)
	msg := sprintf("FEDRAMP-PL-2-system-security-plan: attestation expired (expires_at=%s)", [input.fedramp_pl_2_system_security_plan.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_pl_2_system_security_plan, 365)
	msg := sprintf("FEDRAMP-PL-2-system-security-plan: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_pl_2_system_security_plan.last_review_at])
}

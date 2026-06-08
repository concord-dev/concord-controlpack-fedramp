package concord.fedramp.fedramp_ma_2_controlled_maintenance

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ma_2_controlled_maintenance")
	msg := "FEDRAMP-MA-2-controlled-maintenance: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_ma_2_controlled_maintenance)
	msg := sprintf("FEDRAMP-MA-2-controlled-maintenance: attestation expired (expires_at=%s)", [input.fedramp_ma_2_controlled_maintenance.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_ma_2_controlled_maintenance, 365)
	msg := sprintf("FEDRAMP-MA-2-controlled-maintenance: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_ma_2_controlled_maintenance.last_review_at])
}

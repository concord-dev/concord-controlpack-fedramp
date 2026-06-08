package concord.fedramp.fedramp_ca_7_continuous_monitoring

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_ca_7_continuous_monitoring")
	msg := "FEDRAMP-CA-7-continuous-monitoring: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_ca_7_continuous_monitoring)
	msg := sprintf("FEDRAMP-CA-7-continuous-monitoring: attestation expired (expires_at=%s)", [input.fedramp_ca_7_continuous_monitoring.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_ca_7_continuous_monitoring, 365)
	msg := sprintf("FEDRAMP-CA-7-continuous-monitoring: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_ca_7_continuous_monitoring.last_review_at])
}

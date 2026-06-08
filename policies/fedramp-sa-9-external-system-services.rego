package concord.fedramp.fedramp_sa_9_external_system_services

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_sa_9_external_system_services")
	msg := "FEDRAMP-SA-9-external-system-services: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_sa_9_external_system_services)
	msg := sprintf("FEDRAMP-SA-9-external-system-services: attestation expired (expires_at=%s)", [input.fedramp_sa_9_external_system_services.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_sa_9_external_system_services, 365)
	msg := sprintf("FEDRAMP-SA-9-external-system-services: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_sa_9_external_system_services.last_review_at])
}

package concord.fedramp.fedramp_cp_10_system_recovery_and_reconstitution

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_cp_10_system_recovery_and_reconstitution")
	msg := "FEDRAMP-CP-10-system-recovery-and-reconstitution: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_cp_10_system_recovery_and_reconstitution)
	msg := sprintf("FEDRAMP-CP-10-system-recovery-and-reconstitution: attestation expired (expires_at=%s)", [input.fedramp_cp_10_system_recovery_and_reconstitution.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_cp_10_system_recovery_and_reconstitution, 365)
	msg := sprintf("FEDRAMP-CP-10-system-recovery-and-reconstitution: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_cp_10_system_recovery_and_reconstitution.last_review_at])
}

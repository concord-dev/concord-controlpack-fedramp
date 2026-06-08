package concord.fedramp.fedramp_sa_11_developer_testing_and_evaluation

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_sa_11_developer_testing_and_evaluation")
	msg := "FEDRAMP-SA-11-developer-testing-and-evaluation: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.fedramp_sa_11_developer_testing_and_evaluation)
	msg := sprintf("FEDRAMP-SA-11-developer-testing-and-evaluation: attestation expired (expires_at=%s)", [input.fedramp_sa_11_developer_testing_and_evaluation.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.fedramp_sa_11_developer_testing_and_evaluation, 365)
	msg := sprintf("FEDRAMP-SA-11-developer-testing-and-evaluation: attestation not reviewed in 365 days (last_review_at=%s)", [input.fedramp_sa_11_developer_testing_and_evaluation.last_review_at])
}

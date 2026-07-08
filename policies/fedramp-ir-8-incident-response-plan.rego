package concord.fedramp.ir_8

import rego.v1

# NIST SP 800-53 Rev 5 IR-8 (Incident Response Plan), FedRAMP Moderate. The
# incident response plan is collected from the repository via github/file_glob
# with frontmatter parsing, so each matched file appears in
# input.incident_response_plan_attestation.docs with its frontmatter keys plus
# a "path". The plan must be complete, reviewed and tested within the last
# year, and cosign-verified.

max_review_age_days := 365

max_test_age_days := 365

required_fields := [
	"plan_scope",
	"roles_responsibilities",
	"communication_plan",
	"last_tested_at",
	"last_reviewed_at",
	"signature_verified",
]

deny contains msg if {
	not input.incident_response_plan_attestation
	msg := "FEDRAMP IR-8: no incident-response-plan evidence collected"
}

deny contains msg if {
	input.incident_response_plan_attestation
	count(object.get(input.incident_response_plan_attestation, "docs", [])) == 0
	msg := "FEDRAMP IR-8: no incident-response-plan document found at the configured repository path"
}

deny contains msg if {
	some doc in input.incident_response_plan_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FEDRAMP IR-8: incident response plan %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
	some doc in input.incident_response_plan_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("FEDRAMP IR-8: incident response plan %q was last reviewed %d days ago (IR-8 expects review at least every %d days)", [doc.path, doc.review_age_days, max_review_age_days])
}

deny contains msg if {
	some doc in input.incident_response_plan_attestation.docs
	doc.test_age_days > max_test_age_days
	msg := sprintf("FEDRAMP IR-8: incident response plan %q was last exercised %d days ago (IR-8 expects testing at least every %d days)", [doc.path, doc.test_age_days, max_test_age_days])
}

deny contains msg if {
	some doc in input.incident_response_plan_attestation.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FEDRAMP IR-8: incident response plan %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
}

has_value(doc, key) if {
	v := doc[key]
	not is_blank(v)
}

is_blank(v) if v == null

is_blank(v) if v == ""

is_blank(v) if {
	is_array(v)
	count(v) == 0
}

is_blank(v) if {
	is_object(v)
	count(v) == 0
}

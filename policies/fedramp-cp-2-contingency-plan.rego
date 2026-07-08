package concord.fedramp.cp_2

import rego.v1

# NIST SP 800-53 Rev 5 CP-2 (Contingency Plan), FedRAMP Moderate. The
# contingency plan is collected from the repository via github/file_glob with
# frontmatter parsing, so each matched file appears in
# input.contingency_plan_attestation.docs with its frontmatter keys plus a
# "path". The plan must be complete, reviewed and tested within the last year,
# and cosign-verified.

max_review_age_days := 365

max_test_age_days := 365

required_fields := [
	"roles_responsibilities",
	"recovery_objectives",
	"activation_criteria",
	"last_tested_at",
	"last_reviewed_at",
	"signature_verified",
]

deny contains msg if {
	not input.contingency_plan_attestation
	msg := "FEDRAMP CP-2: no contingency-plan evidence collected"
}

deny contains msg if {
	input.contingency_plan_attestation
	count(object.get(input.contingency_plan_attestation, "docs", [])) == 0
	msg := "FEDRAMP CP-2: no contingency-plan document found at the configured repository path"
}

deny contains msg if {
	some doc in input.contingency_plan_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FEDRAMP CP-2: contingency plan %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
	some doc in input.contingency_plan_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("FEDRAMP CP-2: contingency plan %q was last reviewed %d days ago (CP-2 expects review at least every %d days)", [doc.path, doc.review_age_days, max_review_age_days])
}

deny contains msg if {
	some doc in input.contingency_plan_attestation.docs
	doc.test_age_days > max_test_age_days
	msg := sprintf("FEDRAMP CP-2: contingency plan %q was last tested %d days ago (CP-2 expects the plan to be exercised at least every %d days)", [doc.path, doc.test_age_days, max_test_age_days])
}

deny contains msg if {
	some doc in input.contingency_plan_attestation.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FEDRAMP CP-2: contingency plan %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

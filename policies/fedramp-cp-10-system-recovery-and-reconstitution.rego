package concord.fedramp.cp_10

import rego.v1

# NIST SP 800-53 Rev 5 CP-10 (System Recovery and Reconstitution), FedRAMP
# Moderate. The procedures are collected from the repository via
# github/file_glob with frontmatter parsing, so each matched file appears in
# input.recovery_attestation.docs with its frontmatter keys plus a "path".
# The procedures must be complete, reviewed and tested within the last year,
# and cosign-verified.

max_review_age_days := 365

max_test_age_days := 365

required_fields := [
	"recovery_procedures",
	"reconstitution_steps",
	"last_tested_at",
	"last_reviewed_at",
	"signature_verified",
]

deny contains msg if {
	not input.recovery_attestation
	msg := "FEDRAMP CP-10: no system-recovery-and-reconstitution evidence collected"
}

deny contains msg if {
	input.recovery_attestation
	count(object.get(input.recovery_attestation, "docs", [])) == 0
	msg := "FEDRAMP CP-10: no system-recovery-and-reconstitution document found at the configured repository path"
}

deny contains msg if {
	some doc in input.recovery_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FEDRAMP CP-10: recovery/reconstitution procedures %q are missing required field %q", [doc.path, field])
}

deny contains msg if {
	some doc in input.recovery_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("FEDRAMP CP-10: recovery/reconstitution procedures %q were last reviewed %d days ago (CP-10 expects review at least every %d days)", [doc.path, doc.review_age_days, max_review_age_days])
}

deny contains msg if {
	some doc in input.recovery_attestation.docs
	doc.test_age_days > max_test_age_days
	msg := sprintf("FEDRAMP CP-10: recovery/reconstitution procedures %q were last tested %d days ago (CP-10 expects testing at least every %d days)", [doc.path, doc.test_age_days, max_test_age_days])
}

deny contains msg if {
	some doc in input.recovery_attestation.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FEDRAMP CP-10: recovery/reconstitution procedures %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

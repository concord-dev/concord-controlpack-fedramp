package concord.fedramp.ac_5

import rego.v1

# NIST SP 800-53 Rev 5 AC-5 (Separation of Duties), FedRAMP Moderate.
# The separation-of-duties matrix is collected from the repository via
# github/file_glob with frontmatter parsing, so each matched file appears in
# input.sod_attestation.docs with its frontmatter keys plus a "path".
# The matrix must be complete, current, and cosign-verified.

max_review_age_days := 365

required_fields := [
	"duties_matrix",
	"conflicting_roles_identified",
	"review_process",
	"last_reviewed_at",
	"signature_verified",
]

deny contains msg if {
	not input.sod_attestation
	msg := "FEDRAMP AC-5: no separation-of-duties matrix evidence collected"
}

deny contains msg if {
	input.sod_attestation
	count(object.get(input.sod_attestation, "docs", [])) == 0
	msg := "FEDRAMP AC-5: no separation-of-duties matrix document found at the configured repository path"
}

deny contains msg if {
	some doc in input.sod_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FEDRAMP AC-5: separation-of-duties matrix %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
	some doc in input.sod_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("FEDRAMP AC-5: separation-of-duties matrix %q was last reviewed %d days ago (AC-5 expects review at least every %d days)", [doc.path, doc.review_age_days, max_review_age_days])
}

deny contains msg if {
	some doc in input.sod_attestation.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FEDRAMP AC-5: separation-of-duties matrix %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

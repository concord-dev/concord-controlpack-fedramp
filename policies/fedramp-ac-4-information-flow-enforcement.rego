package concord.fedramp.ac_4

import rego.v1

# NIST SP 800-53 Rev 5 AC-4 (Information Flow Enforcement), FedRAMP Moderate.
# The flow-control policy is collected from the repository via github/file_glob
# with frontmatter parsing, so each matched file appears in
# input.flow_control_attestation.docs with its frontmatter keys plus a "path".
# The policy must be complete, current, and cosign-verified.

max_review_age_days := 365

required_fields := [
	"flow_control_policy",
	"boundary_definitions",
	"enforcement_mechanisms",
	"last_reviewed_at",
	"signature_verified",
]

deny contains msg if {
	not input.flow_control_attestation
	msg := "FEDRAMP AC-4: no information-flow-enforcement policy evidence collected"
}

deny contains msg if {
	input.flow_control_attestation
	count(object.get(input.flow_control_attestation, "docs", [])) == 0
	msg := "FEDRAMP AC-4: no information-flow-enforcement policy document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.flow_control_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FEDRAMP AC-4: flow-control policy %q is missing required field %q", [doc.path, field])
}

# Freshness: the policy must have been reviewed within the last year.
deny contains msg if {
	some doc in input.flow_control_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("FEDRAMP AC-4: flow-control policy %q was last reviewed %d days ago (AC-4 expects review at least every %d days)", [doc.path, doc.review_age_days, max_review_age_days])
}

# Signature must be an explicit boolean true; present-but-not-true (false or a
# string) is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.flow_control_attestation.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FEDRAMP AC-4: flow-control policy %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

package concord.fedramp.ir_4

import rego.v1

# NIST SP 800-53 Rev 5 IR-4 (Incident Handling), FedRAMP Moderate. The
# incident-handling procedure is collected from the repository via
# github/file_glob with frontmatter parsing, so each matched file appears in
# input.incident_handling_attestation.docs with its frontmatter keys plus a
# "path". The procedure must be complete, reviewed and tested within the last
# year, and cosign-verified.

max_review_age_days := 365

max_test_age_days := 365

required_fields := [
	"detection_process",
	"containment_eradication",
	"roles",
	"last_tested_at",
	"last_reviewed_at",
	"signature_verified",
]

deny contains msg if {
	not input.incident_handling_attestation
	msg := "FEDRAMP IR-4: no incident-handling procedure evidence collected"
}

deny contains msg if {
	input.incident_handling_attestation
	count(object.get(input.incident_handling_attestation, "docs", [])) == 0
	msg := "FEDRAMP IR-4: no incident-handling procedure document found at the configured repository path"
}

deny contains msg if {
	some doc in input.incident_handling_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FEDRAMP IR-4: incident-handling procedure %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
	some doc in input.incident_handling_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("FEDRAMP IR-4: incident-handling procedure %q was last reviewed %d days ago (IR-4 expects review at least every %d days)", [doc.path, doc.review_age_days, max_review_age_days])
}

deny contains msg if {
	some doc in input.incident_handling_attestation.docs
	doc.test_age_days > max_test_age_days
	msg := sprintf("FEDRAMP IR-4: incident-handling procedure %q was last exercised %d days ago (IR-4 expects testing at least every %d days)", [doc.path, doc.test_age_days, max_test_age_days])
}

deny contains msg if {
	some doc in input.incident_handling_attestation.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FEDRAMP IR-4: incident-handling procedure %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

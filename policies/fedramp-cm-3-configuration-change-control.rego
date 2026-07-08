package concord.fedramp.cm_3_configuration_change_control

import rego.v1

# NIST 800-53 Rev 5 CM-3 / FedRAMP Moderate — Configuration Change Control.
# CM-3 requires changes to the system to be proposed, reviewed, approved (or
# disapproved) with explicit consideration of security impact, tested before
# implementation, and to have a documented way to back the change out. Concord
# reads the version-controlled change-control procedure from the repository via
# github/file_glob with frontmatter parsing, so each matched file appears in
# input.change_control.docs with its frontmatter keys plus a "path".
# Fail-closed on missing evidence, no document, a missing field, a procedure
# not reviewed within a year, or an unverified signature.

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["change_approval_process", "testing_requirement", "rollback_procedure", "last_reviewed_at", "signature_verified"]

deny contains msg if {
	not input.change_control
	msg := "FedRAMP CM-3: no configuration-change-control evidence collected"
}

deny contains msg if {
	input.change_control
	count(object.get(input.change_control, "docs", [])) == 0
	msg := "FedRAMP CM-3: no change-control document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.change_control.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FedRAMP CM-3: change-control procedure %q is missing required field %q", [doc.path, field])
}

# Freshness: the procedure must have been reviewed within the last year.
deny contains msg if {
	some doc in input.change_control.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("FedRAMP CM-3: change-control procedure %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.change_control.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FedRAMP CM-3: change-control procedure %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

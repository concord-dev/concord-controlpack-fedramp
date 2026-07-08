package concord.fedramp.pl_2

import rego.v1

# NIST SP 800-53 Rev 5 PL-2 (System Security Plan) — FedRAMP Moderate.
# The organisation must develop and maintain a system security plan (SSP) that
# describes the authorisation boundary, summarises how each control is
# implemented, and identifies the individuals/roles responsible, and it must be
# reviewed on a defined cadence. Concord reads the version-controlled SSP
# metadata via github/file_glob with frontmatter parsing, so each matched file
# appears in input.system_security_plan.docs with its frontmatter keys plus a
# "path".

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["system_boundary", "control_implementation_summary", "roles", "last_reviewed_at", "signature_verified"]

deny contains msg if {
	not input.system_security_plan
	msg := "FedRAMP PL-2: no system-security-plan evidence collected"
}

deny contains msg if {
	input.system_security_plan
	count(object.get(input.system_security_plan, "docs", [])) == 0
	msg := "FedRAMP PL-2: no system-security-plan document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.system_security_plan.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FedRAMP PL-2: system-security-plan %q is missing required field %q", [doc.path, field])
}

# Freshness: the SSP must have been reviewed within the last year.
deny contains msg if {
	some doc in input.system_security_plan.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("FedRAMP PL-2: system-security-plan %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.system_security_plan.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FedRAMP PL-2: system-security-plan %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

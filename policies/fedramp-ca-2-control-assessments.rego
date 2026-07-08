package concord.fedramp.ca_2_control_assessments

import rego.v1

# NIST 800-53 Rev 5 CA-2 / FedRAMP Moderate — Control Assessments.
# CA-2 requires security and privacy controls to be assessed for effectiveness
# on an organization-defined frequency by an assessor, against a defined scope,
# with the results (findings) documented and tracked. Concord reads the
# version-controlled control-assessment record from the repository via
# github/file_glob with frontmatter parsing, so each matched file appears in
# input.control_assessment.docs with its frontmatter keys plus a "path".
# Fail-closed on missing evidence, no document, a missing field, an assessment
# older than a year, or an unverified signature.

max_assessment_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["assessor", "scope", "last_assessment_at", "findings_status", "signature_verified"]

deny contains msg if {
	not input.control_assessment
	msg := "FedRAMP CA-2: no control-assessment evidence collected"
}

deny contains msg if {
	input.control_assessment
	count(object.get(input.control_assessment, "docs", [])) == 0
	msg := "FedRAMP CA-2: no control-assessment document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.control_assessment.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FedRAMP CA-2: control assessment %q is missing required field %q", [doc.path, field])
}

# Freshness: controls must have been assessed within the last year.
deny contains msg if {
	some doc in input.control_assessment.docs
	has_value(doc, "last_assessment_at")
	assessed_ns := time.parse_rfc3339_ns(doc.last_assessment_at)
	cutoff_ns := time.now_ns() - (max_assessment_age_days * nanos_per_day)
	assessed_ns < cutoff_ns
	msg := sprintf("FedRAMP CA-2: control assessment %q was last performed more than %d days ago (last_assessment_at=%s)", [doc.path, max_assessment_age_days, doc.last_assessment_at])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.control_assessment.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FedRAMP CA-2: control assessment %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

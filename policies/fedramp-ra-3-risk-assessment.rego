package concord.fedramp.ra_3_risk_assessment

import rego.v1

# NIST 800-53 Rev 5 RA-3 / FedRAMP Moderate — Risk Assessment.
# RA-3 requires the organization to conduct a risk assessment of the system,
# document the results, and update the assessment on a defined cadence and when
# significant changes occur. The assessment itself — its methodology, scope,
# the finding-tracking mechanism, and the date it was last performed — is
# auditable evidence. Concord reads the version-controlled risk-assessment
# document from the repository via github/file_glob with frontmatter parsing,
# so each matched file appears in input.risk_assessment.docs with its
# frontmatter keys plus a "path". Fail-closed on missing evidence, no document,
# a missing field, an assessment older than a year, or an unverified signature.

max_assessment_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["methodology", "scope", "last_assessment_at", "findings_tracked", "signature_verified"]

deny contains msg if {
	not input.risk_assessment
	msg := "FedRAMP RA-3: no risk-assessment evidence collected"
}

deny contains msg if {
	input.risk_assessment
	count(object.get(input.risk_assessment, "docs", [])) == 0
	msg := "FedRAMP RA-3: no risk-assessment document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.risk_assessment.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FedRAMP RA-3: risk assessment %q is missing required field %q", [doc.path, field])
}

# Freshness: the assessment must have been performed within the last year.
deny contains msg if {
	some doc in input.risk_assessment.docs
	has_value(doc, "last_assessment_at")
	assessed_ns := time.parse_rfc3339_ns(doc.last_assessment_at)
	cutoff_ns := time.now_ns() - (max_assessment_age_days * nanos_per_day)
	assessed_ns < cutoff_ns
	msg := sprintf("FedRAMP RA-3: risk assessment %q was last performed more than %d days ago (last_assessment_at=%s)", [doc.path, max_assessment_age_days, doc.last_assessment_at])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.risk_assessment.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FedRAMP RA-3: risk assessment %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

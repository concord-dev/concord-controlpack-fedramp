package concord.fedramp.ir_6

import rego.v1

# NIST SP 800-53 Rev 5 IR-6 (Incident Reporting), FedRAMP Moderate. The
# incident-reporting procedure is collected from the repository via
# github/file_glob with frontmatter parsing, so each matched file appears in
# input.incident_reporting_attestation.docs with its frontmatter keys plus a
# "path". The procedure must name the reporting timeframes, the authorities to
# be notified (including US-CERT), and the escalation path; it must be current
# and cosign-verified.

max_review_age_days := 365

required_fields := [
	"reporting_timeframes",
	"authorities_notified",
	"escalation_path",
	"last_reviewed_at",
	"signature_verified",
]

deny contains msg if {
	not input.incident_reporting_attestation
	msg := "FEDRAMP IR-6: no incident-reporting procedure evidence collected"
}

deny contains msg if {
	input.incident_reporting_attestation
	count(object.get(input.incident_reporting_attestation, "docs", [])) == 0
	msg := "FEDRAMP IR-6: no incident-reporting procedure document found at the configured repository path"
}

deny contains msg if {
	some doc in input.incident_reporting_attestation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FEDRAMP IR-6: incident-reporting procedure %q is missing required field %q", [doc.path, field])
}

# FedRAMP requires US-CERT/CISA to be among the notified authorities.
deny contains msg if {
	some doc in input.incident_reporting_attestation.docs
	has_value(doc, "authorities_notified")
	not mentions_us_cert(doc.authorities_notified)
	msg := sprintf("FEDRAMP IR-6: incident-reporting procedure %q does not name US-CERT/CISA among the authorities to be notified", [doc.path])
}

deny contains msg if {
	some doc in input.incident_reporting_attestation.docs
	doc.review_age_days > max_review_age_days
	msg := sprintf("FEDRAMP IR-6: incident-reporting procedure %q was last reviewed %d days ago (IR-6 expects review at least every %d days)", [doc.path, doc.review_age_days, max_review_age_days])
}

deny contains msg if {
	some doc in input.incident_reporting_attestation.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FEDRAMP IR-6: incident-reporting procedure %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
}

mentions_us_cert(v) if {
	is_string(v)
	contains(lower(v), "us-cert")
}

mentions_us_cert(v) if {
	is_string(v)
	contains(lower(v), "cisa")
}

mentions_us_cert(v) if {
	is_array(v)
	some entry in v
	is_string(entry)
	contains(lower(entry), "us-cert")
}

mentions_us_cert(v) if {
	is_array(v)
	some entry in v
	is_string(entry)
	contains(lower(entry), "cisa")
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

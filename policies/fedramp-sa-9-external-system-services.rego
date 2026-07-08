package concord.fedramp.sa_9_external_system_services

import rego.v1

# NIST 800-53 Rev 5 SA-9 / FedRAMP Moderate — External System Services.
# SA-9 requires providers of external system services (SaaS, subservice
# organizations, and other third parties) to comply with defined security
# requirements, and requires the organization to define and monitor those
# services on an ongoing basis. Concord reads the version-controlled external-
# services governance record from the repository via github/file_glob with
# frontmatter parsing, so each matched file appears in
# input.external_services.docs with its frontmatter keys plus a "path".
# Fail-closed on missing evidence, no document, a missing field, a record not
# reviewed within a year, or an unverified signature.

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["service_inventory", "security_requirements", "monitoring_process", "last_reviewed_at", "signature_verified"]

deny contains msg if {
	not input.external_services
	msg := "FedRAMP SA-9: no external-system-services evidence collected"
}

deny contains msg if {
	input.external_services
	count(object.get(input.external_services, "docs", [])) == 0
	msg := "FedRAMP SA-9: no external-services governance document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.external_services.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FedRAMP SA-9: external-services record %q is missing required field %q", [doc.path, field])
}

# Freshness: the external-services governance must have been reviewed within
# the last year.
deny contains msg if {
	some doc in input.external_services.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("FedRAMP SA-9: external-services record %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.external_services.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FedRAMP SA-9: external-services record %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

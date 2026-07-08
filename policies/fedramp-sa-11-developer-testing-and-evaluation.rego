package concord.fedramp.sa_11_developer_testing_and_evaluation

import rego.v1

# NIST 800-53 Rev 5 SA-11 / FedRAMP Moderate — Developer Testing and
# Evaluation. SA-11 requires the developer of the system, component, or service
# to perform security testing and evaluation (for example static analysis
# (SAST), dynamic analysis (DAST), and dependency scanning) at a defined
# frequency and to track and remediate the flaws that testing uncovers. Concord
# reads the version-controlled developer-testing record from the repository via
# github/file_glob with frontmatter parsing, so each matched file appears in
# input.developer_testing.docs with its frontmatter keys plus a "path".
# Fail-closed on missing evidence, no document, a missing field, testing not
# performed within a year, or an unverified signature.

max_testing_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["testing_types", "frequency", "last_performed_at", "remediation_tracking", "signature_verified"]

deny contains msg if {
	not input.developer_testing
	msg := "FedRAMP SA-11: no developer-testing evidence collected"
}

deny contains msg if {
	input.developer_testing
	count(object.get(input.developer_testing, "docs", [])) == 0
	msg := "FedRAMP SA-11: no developer-testing document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.developer_testing.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FedRAMP SA-11: developer-testing record %q is missing required field %q", [doc.path, field])
}

# Freshness: developer security testing must have been performed within the
# last year.
deny contains msg if {
	some doc in input.developer_testing.docs
	has_value(doc, "last_performed_at")
	performed_ns := time.parse_rfc3339_ns(doc.last_performed_at)
	cutoff_ns := time.now_ns() - (max_testing_age_days * nanos_per_day)
	performed_ns < cutoff_ns
	msg := sprintf("FedRAMP SA-11: developer security testing %q was last performed more than %d days ago (last_performed_at=%s)", [doc.path, max_testing_age_days, doc.last_performed_at])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.developer_testing.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FedRAMP SA-11: developer-testing record %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

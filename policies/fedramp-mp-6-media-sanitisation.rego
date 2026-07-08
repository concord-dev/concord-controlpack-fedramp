package concord.fedramp.mp_6

import rego.v1

# NIST SP 800-53 Rev 5 MP-6 (Media Sanitization) — FedRAMP Moderate.
# System media must be sanitised prior to disposal, release out of
# organisational control, or reuse, using techniques and procedures consistent
# with NIST SP 800-88. Media sanitisation is a physical / procedural activity
# that is not observable through cloud telemetry, so Concord evaluates a signed,
# version-controlled attestation of the sanitisation program. The attestation is
# collected via github/file_glob with frontmatter parsing, so each matched file
# appears in input.media_sanitisation.docs with its frontmatter keys plus a
# "path".

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["sanitisation_method", "verification_process", "last_reviewed_at", "signature_verified"]

# NIST SP 800-88 Rev 1 recognised sanitisation categories. Anything outside this
# set (e.g. "factory_reset", "quick_format", "delete") does not render data
# unrecoverable and must fail.
approved_sanitisation_methods := {"clear", "purge", "destroy", "crypto_erase"}

deny contains msg if {
	not input.media_sanitisation
	msg := "FedRAMP MP-6: no media-sanitisation attestation evidence collected"
}

deny contains msg if {
	input.media_sanitisation
	count(object.get(input.media_sanitisation, "docs", [])) == 0
	msg := "FedRAMP MP-6: no media-sanitisation attestation document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.media_sanitisation.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FedRAMP MP-6: media-sanitisation attestation %q is missing required field %q", [doc.path, field])
}

# The declared sanitisation method must be a NIST SP 800-88 approved technique.
deny contains msg if {
	some doc in input.media_sanitisation.docs
	has_value(doc, "sanitisation_method")
	not doc.sanitisation_method in approved_sanitisation_methods
	msg := sprintf("FedRAMP MP-6: media-sanitisation attestation %q declares method %q, which is not a NIST SP 800-88 approved technique (clear, purge, destroy, crypto_erase)", [doc.path, doc.sanitisation_method])
}

# Freshness: the attestation must have been reviewed within the last year.
deny contains msg if {
	some doc in input.media_sanitisation.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("FedRAMP MP-6: media-sanitisation attestation %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.media_sanitisation.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FedRAMP MP-6: media-sanitisation attestation %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

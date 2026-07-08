package concord.fedramp.mp_4

import rego.v1

# NIST SP 800-53 Rev 5 MP-4 (Media Storage) — FedRAMP Moderate.
# Digital and non-digital media must be physically controlled and securely
# stored within controlled areas, with access restricted to authorised
# personnel. Physical media handling is not observable through cloud APIs, so
# Concord evaluates a signed, version-controlled attestation of the media-storage
# program. The attestation is collected via github/file_glob with frontmatter
# parsing, so each matched file appears in input.media_storage.docs with its
# frontmatter keys plus a "path".

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["storage_controls", "media_inventory", "access_restrictions", "last_reviewed_at", "signature_verified"]

deny contains msg if {
	not input.media_storage
	msg := "FedRAMP MP-4: no media-storage attestation evidence collected"
}

deny contains msg if {
	input.media_storage
	count(object.get(input.media_storage, "docs", [])) == 0
	msg := "FedRAMP MP-4: no media-storage attestation document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.media_storage.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FedRAMP MP-4: media-storage attestation %q is missing required field %q", [doc.path, field])
}

# Freshness: the attestation must have been reviewed within the last year.
deny contains msg if {
	some doc in input.media_storage.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("FedRAMP MP-4: media-storage attestation %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.media_storage.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FedRAMP MP-4: media-storage attestation %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

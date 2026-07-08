package concord.fedramp.pe_3

import rego.v1

# NIST SP 800-53 Rev 5 PE-3 (Physical Access Control) — FedRAMP Moderate.
# Physical access authorisations must be enforced at defined entry/exit points
# to facilities housing the system: access is verified before granting entry,
# ingress/egress is controlled, and visitors are logged. Physical access is not
# observable through cloud APIs, so Concord evaluates a signed, version-controlled
# attestation of the physical access-control program. The attestation is
# collected via github/file_glob with frontmatter parsing, so each matched file
# appears in input.physical_access.docs with its frontmatter keys plus a "path".

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["access_authorisations", "access_points_controlled", "visitor_logging", "last_reviewed_at", "signature_verified"]

deny contains msg if {
	not input.physical_access
	msg := "FedRAMP PE-3: no physical-access-control attestation evidence collected"
}

deny contains msg if {
	input.physical_access
	count(object.get(input.physical_access, "docs", [])) == 0
	msg := "FedRAMP PE-3: no physical-access-control attestation document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.physical_access.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FedRAMP PE-3: physical-access-control attestation %q is missing required field %q", [doc.path, field])
}

# Access points must be affirmatively controlled — an explicit boolean true.
deny contains msg if {
	some doc in input.physical_access.docs
	has_value(doc, "access_points_controlled")
	not doc.access_points_controlled == true
	msg := sprintf("FedRAMP PE-3: physical-access-control attestation %q does not confirm access points are controlled (access_points_controlled=%v)", [doc.path, doc.access_points_controlled])
}

# Visitor logging must be affirmatively in force — an explicit boolean true.
deny contains msg if {
	some doc in input.physical_access.docs
	has_value(doc, "visitor_logging")
	not doc.visitor_logging == true
	msg := sprintf("FedRAMP PE-3: physical-access-control attestation %q does not confirm visitor access is logged (visitor_logging=%v)", [doc.path, doc.visitor_logging])
}

# Freshness: the attestation must have been reviewed within the last year.
deny contains msg if {
	some doc in input.physical_access.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("FedRAMP PE-3: physical-access-control attestation %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.physical_access.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FedRAMP PE-3: physical-access-control attestation %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

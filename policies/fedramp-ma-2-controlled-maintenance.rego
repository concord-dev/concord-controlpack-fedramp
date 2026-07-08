package concord.fedramp.ma_2

import rego.v1

# NIST SP 800-53 Rev 5 MA-2 (Controlled Maintenance) — FedRAMP Moderate.
# Maintenance and repair on system components must be scheduled, approved,
# recorded, and any component that leaves the facility for off-site maintenance
# must have its media sanitised first. Off-site maintenance is a physical /
# procedural activity that is not observable through cloud telemetry, so
# Concord evaluates a signed, version-controlled attestation of the controlled
# maintenance program. The attestation is collected via github/file_glob with
# frontmatter parsing, so each matched file appears in
# input.maintenance_records.docs with its frontmatter keys plus a "path".

max_review_age_days := 365

nanos_per_day := 86400000000000

required_fields := ["maintenance_approval_process", "records_retention", "sanitisation_before_offsite", "last_reviewed_at", "signature_verified"]

deny contains msg if {
	not input.maintenance_records
	msg := "FedRAMP MA-2: no controlled-maintenance attestation evidence collected"
}

deny contains msg if {
	input.maintenance_records
	count(object.get(input.maintenance_records, "docs", [])) == 0
	msg := "FedRAMP MA-2: no controlled-maintenance attestation document found at the configured repository path"
}

# Every required field must be present and non-empty (absent, empty string,
# and empty collection all count as missing).
deny contains msg if {
	some doc in input.maintenance_records.docs
	some field in required_fields
	not has_value(doc, field)
	msg := sprintf("FedRAMP MA-2: controlled-maintenance attestation %q is missing required field %q", [doc.path, field])
}

# Freshness: the attestation must have been reviewed within the last year.
deny contains msg if {
	some doc in input.maintenance_records.docs
	has_value(doc, "last_reviewed_at")
	reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
	cutoff_ns := time.now_ns() - (max_review_age_days * nanos_per_day)
	reviewed_ns < cutoff_ns
	msg := sprintf("FedRAMP MA-2: controlled-maintenance attestation %q was last reviewed more than %d days ago (last_reviewed_at=%s)", [doc.path, max_review_age_days, doc.last_reviewed_at])
}

# Off-site sanitisation must be an explicit boolean true — a component sent out
# for repair with data still on it is a direct MA-2 / MP-6 breach.
deny contains msg if {
	some doc in input.maintenance_records.docs
	has_value(doc, "sanitisation_before_offsite")
	not doc.sanitisation_before_offsite == true
	msg := sprintf("FedRAMP MA-2: controlled-maintenance attestation %q does not confirm media sanitisation before off-site maintenance (sanitisation_before_offsite=%v)", [doc.path, doc.sanitisation_before_offsite])
}

# Signature must be an explicit boolean true. Present-but-not-true (e.g. false
# or the string "true") is a distinct, reported failure from an absent field.
deny contains msg if {
	some doc in input.maintenance_records.docs
	has_value(doc, "signature_verified")
	not doc.signature_verified == true
	msg := sprintf("FedRAMP MA-2: controlled-maintenance attestation %q signature is not verified (signature_verified=%v)", [doc.path, doc.signature_verified])
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

package concord.fedramp.sc_13

import rego.v1

# NIST 800-53 Rev 5 SC-13 (Cryptographic Protection) / FedRAMP Moderate —
# cryptography protecting federal information must use FIPS-validated
# mechanisms. Concord requires every S3 bucket and RDS instance to be encrypted
# with a customer-managed KMS key (SSE-S3/AES256 alone is not FIPS-controllable)
# and denies any KMS key explicitly signalled as not FIPS-validated.
#
# Reused from concord-controlpack-pci-dss r_3_4 (render PAN unreadable) and
# key_management (KMS). Evidence: input.crypto_resources.{buckets,rds_instances,kms_keys}.

deny contains msg if {
	not input.crypto_resources
	msg := "SC-13: no cryptographic-protection evidence collected"
}

# Data store with no encryption at all.
deny contains msg if {
	some b in input.crypto_resources.buckets
	not b.encryption.configured
	msg := sprintf("SC-13: S3 bucket %q has no server-side encryption configured (NIST 800-53 SC-13 / FedRAMP Moderate)", [b.name])
}

# Data store encrypted only with SSE-S3 (AES256) rather than a FIPS-validated
# customer-managed KMS key.
deny contains msg if {
	some b in input.crypto_resources.buckets
	b.encryption.configured
	some rule in b.encryption.rules
	rule.sse_algorithm == "AES256"
	msg := sprintf("SC-13: S3 bucket %q uses AES256 (SSE-S3); FedRAMP requires a FIPS-validated customer-managed KMS key (NIST 800-53 SC-13)", [b.name])
}

deny contains msg if {
	some r in input.crypto_resources.rds_instances
	not r.encryption.configured
	msg := sprintf("SC-13: RDS instance %q has no encryption-at-rest configured (NIST 800-53 SC-13 / FedRAMP Moderate)", [r.identifier])
}

# KMS key explicitly signalled as not FIPS 140-validated.
deny contains msg if {
	some k in input.crypto_resources.kms_keys
	k.fips_validated == false
	msg := sprintf("SC-13: KMS key %q is not FIPS 140-validated; only FIPS-validated cryptographic modules may protect federal information (NIST 800-53 SC-13 / FedRAMP Moderate)", [k.key_id])
}

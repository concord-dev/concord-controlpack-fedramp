package concord.fedramp.sc_28

import rego.v1

# NIST 800-53 Rev 5 SC-28 (Protection of Information at Rest) with SC-28(1)
# cryptographic protection / FedRAMP Moderate — every data store in the
# authorization boundary must have encryption-at-rest enabled. Concord checks
# S3 buckets, RDS instances, and EBS volumes and fails closed for any store
# with no encryption configured.
#
# Reused from concord-controlpack-hipaa encryption (§164.312(a)(2)(iv)) and
# concord-controlpack-nist-800-53 SC-28. Evidence:
# input.encryption_at_rest.{buckets,rds_instances,ebs_volumes}.

deny contains msg if {
	not input.encryption_at_rest
	msg := "SC-28: no encryption-at-rest evidence collected"
}

deny contains msg if {
	some b in input.encryption_at_rest.buckets
	not b.encryption.configured
	msg := sprintf("SC-28: S3 bucket %q has no encryption-at-rest configured (NIST 800-53 SC-28 / FedRAMP Moderate)", [b.name])
}

deny contains msg if {
	some r in input.encryption_at_rest.rds_instances
	not r.encryption.configured
	msg := sprintf("SC-28: RDS instance %q has no encryption-at-rest configured (NIST 800-53 SC-28 / FedRAMP Moderate)", [r.identifier])
}

deny contains msg if {
	some v in input.encryption_at_rest.ebs_volumes
	not v.encryption.configured
	msg := sprintf("SC-28: EBS volume %q has no encryption-at-rest configured (NIST 800-53 SC-28 / FedRAMP Moderate)", [v.volume_id])
}

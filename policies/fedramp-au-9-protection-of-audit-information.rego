package concord.fedramp.au_9

import rego.v1

# NIST 800-53 AU-9 (Protection of Audit Information) / FedRAMP Moderate — audit
# information and audit logging tools must be protected from unauthorised
# access, modification, and deletion. Concord verifies that every logging
# CloudTrail trail has log-file validation enabled (so records are
# tamper-evident), is encrypted with a KMS key (so audit data is protected at
# rest), and stores its logs in an S3 bucket that is not publicly accessible (so
# access is restricted). Fail closed when no trail is present.

trails := input.audit_trail.cloudtrail.trails

deny contains msg if {
	not input.audit_trail
	msg := "no CloudTrail evidence collected"
}

deny contains msg if {
	input.audit_trail
	count(trails) == 0
	msg := "no CloudTrail trail present; audit information cannot be shown to be protected — failing closed (NIST 800-53 AU-9 / FedRAMP Moderate)"
}

deny contains msg if {
	some trail in trails
	not trail.log_file_validation_enabled
	msg := sprintf("CloudTrail trail %q has log-file validation disabled; audit records are not protected from undetected modification (NIST 800-53 AU-9 / FedRAMP Moderate)", [trail.name])
}

deny contains msg if {
	some trail in trails
	not trail.kms_key_id
	msg := sprintf("CloudTrail trail %q is not encrypted with a KMS key; audit information is not protected at rest (NIST 800-53 AU-9 / FedRAMP Moderate)", [trail.name])
}

deny contains msg if {
	some trail in trails
	trail.s3_bucket_is_public == true
	msg := sprintf("CloudTrail trail %q stores logs in a publicly accessible S3 bucket; access to audit information is not restricted (NIST 800-53 AU-9 / FedRAMP Moderate)", [trail.name])
}

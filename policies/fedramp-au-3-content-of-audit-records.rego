package concord.fedramp.au_3

import rego.v1

# NIST 800-53 AU-3 (Content of Audit Records) / FedRAMP Moderate — each audit
# record must capture what type of event occurred, when and where it occurred,
# its source, its outcome, and the identity of the associated subjects. Concord
# verifies the CloudTrail flags that make these fields complete and trustworthy:
# global service events must be included so identity and origin are recorded for
# IAM/STS actions, management events must be recorded so event type, source, and
# name are captured, and log-file validation must be enabled so records are
# tamper-evident. Fail closed when no trail is present.

trails := input.audit_trail_detail.cloudtrail.trails

deny contains msg if {
	not input.audit_trail_detail
	msg := "no audit-trail evidence collected"
}

deny contains msg if {
	input.audit_trail_detail
	count(trails) == 0
	msg := "no CloudTrail trail present; audit-record content cannot be verified — failing closed (NIST 800-53 AU-3 / FedRAMP Moderate)"
}

deny contains msg if {
	some trail in trails
	not trail.include_global_service_events
	msg := sprintf("CloudTrail trail %q excludes global service events; subject identity and origin for IAM/STS actions are not recorded (NIST 800-53 AU-3 / FedRAMP Moderate)", [trail.name])
}

deny contains msg if {
	some trail in trails
	not trail.include_management_events
	msg := sprintf("CloudTrail trail %q does not record management events; event type, source, and name are not captured (NIST 800-53 AU-3 / FedRAMP Moderate)", [trail.name])
}

deny contains msg if {
	some trail in trails
	not trail.log_file_validation_enabled
	msg := sprintf("CloudTrail trail %q has log-file validation disabled; audit records are not tamper-evident (NIST 800-53 AU-3 / FedRAMP Moderate)", [trail.name])
}

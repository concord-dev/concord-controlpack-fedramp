package concord.fedramp.au_6

import rego.v1

# NIST 800-53 AU-6 (Audit Record Review, Analysis, and Reporting) / FedRAMP
# Moderate — audit records must be reviewed and analysed for indications of
# inappropriate or unusual activity, with findings reported to responders.
# Concord verifies that AWS CloudWatch metric alarms (an accepted automated
# review mechanism) cover every required security-event category and that each
# alarm has a wired-up notification action. Fail closed when no evidence is
# present.

required_categories := {
	"unauthorized_api_calls",
	"root_account_usage",
	"iam_policy_changes",
	"console_signin_failures",
}

deny contains msg if {
	not input.log_review
	msg := "no CloudWatch metric-alarm evidence collected"
}

deny contains msg if {
	input.log_review
	some cat in required_categories
	not covered(cat)
	msg := sprintf("no CloudWatch metric alarm with an active notification reviews security-event category %q (NIST 800-53 AU-6 / FedRAMP Moderate)", [cat])
}

deny contains msg if {
	some a in input.log_review.metric_alarms
	a.alarm_configured == true
	count(a.alarm_actions) == 0
	msg := sprintf("CloudWatch metric alarm %q has no notification action; %q events would not be reported for review (NIST 800-53 AU-6 / FedRAMP Moderate)", [a.name, a.covers])
}

covered(cat) if {
	some a in input.log_review.metric_alarms
	a.covers == cat
	a.alarm_configured == true
	count(a.alarm_actions) > 0
}

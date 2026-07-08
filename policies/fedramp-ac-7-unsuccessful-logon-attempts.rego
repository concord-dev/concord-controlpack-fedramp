package concord.fedramp.unsuccessful_logon_attempts

import rego.v1

# NIST SP 800-53 Rev 5 AC-7 (Unsuccessful Logon Attempts) / FedRAMP Moderate.
# AC-7 requires enforcing a limit on consecutive invalid logon attempts and
# taking action when that limit is exceeded. Because the AWS console does not
# natively lock accounts, the compensating detective control is a CloudWatch
# Logs metric filter over the CloudTrail log group that matches failed console
# authentications, wired to a CloudWatch alarm with an active notification
# action. Concord fails the control when no metric filter matches failed
# ConsoleLogin events, or when a matching filter's metric has no alarm with an
# enabled notification action.
# Evidence: input.cloudwatch_alarms.{metric_filters,alarms}.

# Fail closed: no metric-filter/alarm evidence means failed logons are unwatched.
deny contains msg if {
	not input.cloudwatch_alarms
	msg := "no CloudWatch metric-filter/alarm evidence collected — cannot verify repeated failed logons are detected (NIST 800-53 AC-7 / FedRAMP Moderate)"
}

# No metric filter matches failed console log-ins at all.
deny contains msg if {
	input.cloudwatch_alarms
	count(console_failure_filters) == 0
	msg := "no CloudWatch metric filter matches failed console log-ins (ConsoleLogin + \"Failed authentication\") — repeated invalid logon attempts cannot be detected (NIST 800-53 AC-7 / FedRAMP Moderate)"
}

# A matching filter exists but its metric has no alarm with a live action.
deny contains msg if {
	some f in console_failure_filters
	not metric_has_active_alarm(f.metric_name)
	msg := sprintf("metric filter %q matches failed console log-ins but its metric has no CloudWatch alarm with an enabled notification action — nobody is alerted when the invalid-logon limit is exceeded (NIST 800-53 AC-7 / FedRAMP Moderate)", [f.filter_name])
}

console_failure_filters contains f if {
	some f in input.cloudwatch_alarms.metric_filters
	contains(f.filter_pattern, "ConsoleLogin")
	contains(f.filter_pattern, "Failed authentication")
}

metric_has_active_alarm(metric) if {
	some a in input.cloudwatch_alarms.alarms
	a.metric_name == metric
	a.actions_enabled == true
	count(a.alarm_actions) > 0
}

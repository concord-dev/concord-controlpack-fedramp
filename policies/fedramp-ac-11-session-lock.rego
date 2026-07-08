package concord.fedramp.session_lock

import rego.v1

# NIST SP 800-53 Rev 5 AC-11 (Session Lock) / FedRAMP Moderate.
# FedRAMP Moderate parameterizes AC-11 to initiate a session lock after 15
# minutes of inactivity. For interactive AWS access (Management Console and IAM
# Identity Center), the configured idle-lock timeout is the enforcing control.
# Concord fails any IAM role scoped to interactive human use whose configured
# idle session-lock timeout exceeds 900 seconds, and fails closed on any
# interactive role that publishes no idle-lock setting at all.
# Evidence: input.iam_roles.roles[].

# FedRAMP Moderate AC-11 idle threshold: 15 minutes.
max_idle_seconds := 900

# Fail closed: without role evidence the idle-lock posture is unproven.
deny contains msg if {
	not input.iam_roles
	msg := "no IAM role evidence collected — cannot verify session lock on inactivity (NIST 800-53 AC-11 / FedRAMP Moderate)"
}

# Fail closed: an interactive role that publishes no idle-lock timeout.
deny contains msg if {
	some r in input.iam_roles.roles
	is_interactive(r)
	not has_idle_lock(r)
	msg := sprintf("interactive role %q publishes no idle session-lock timeout — session lock on inactivity cannot be verified (NIST 800-53 AC-11 / FedRAMP Moderate)", [r.role_name])
}

# Interactive role whose idle-lock timeout exceeds the 15-minute threshold.
deny contains msg if {
	some r in input.iam_roles.roles
	is_interactive(r)
	has_idle_lock(r)
	r.idle_session_lock_seconds > max_idle_seconds
	msg := sprintf("interactive role %q allows %d seconds of inactivity before session lock, exceeding the %d-second (15-minute) threshold (NIST 800-53 AC-11 / FedRAMP Moderate)", [r.role_name, r.idle_session_lock_seconds, max_idle_seconds])
}

is_interactive(r) if {
	r.tags.session_type == "interactive"
}

has_idle_lock(r) if {
	is_number(r.idle_session_lock_seconds)
}

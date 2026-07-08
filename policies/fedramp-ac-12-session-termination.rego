package concord.fedramp.session_termination

import rego.v1

# NIST SP 800-53 Rev 5 AC-12 (Session Termination) / FedRAMP Moderate.
# The system must automatically terminate a user session after defined
# conditions. For federated and assumed AWS access, the hard ceiling on a
# session is the role's MaxSessionDuration: once it elapses the session ends
# and re-authentication is required. Concord fails any IAM role scoped to
# interactive human use whose max_session_duration_seconds exceeds the
# 3600-second (one-hour) threshold, and fails closed on any interactive role
# that does not publish a max session duration.
# Evidence: input.iam_roles.roles[].

# One-hour ceiling on an interactive session before forced re-authentication.
max_session_seconds := 3600

# Fail closed: without role evidence session termination is unproven.
deny contains msg if {
	not input.iam_roles
	msg := "no IAM role evidence collected — cannot verify automatic session termination (NIST 800-53 AC-12 / FedRAMP Moderate)"
}

# Fail closed: an interactive role with no published max session duration.
deny contains msg if {
	some r in input.iam_roles.roles
	is_interactive(r)
	not has_max_session(r)
	msg := sprintf("interactive role %q does not publish a max session duration — automatic session termination cannot be verified (NIST 800-53 AC-12 / FedRAMP Moderate)", [r.role_name])
}

# Interactive role whose session ceiling exceeds the one-hour threshold.
deny contains msg if {
	some r in input.iam_roles.roles
	is_interactive(r)
	has_max_session(r)
	r.max_session_duration_seconds > max_session_seconds
	msg := sprintf("interactive role %q allows sessions of %d seconds, exceeding the %d-second (one-hour) automatic-termination threshold (NIST 800-53 AC-12 / FedRAMP Moderate)", [r.role_name, r.max_session_duration_seconds, max_session_seconds])
}

is_interactive(r) if {
	r.tags.session_type == "interactive"
}

has_max_session(r) if {
	is_number(r.max_session_duration_seconds)
}

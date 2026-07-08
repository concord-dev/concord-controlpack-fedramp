package concord.fedramp.ps_4

import rego.v1

# NIST SP 800-53 Rev 5 PS-4 (Personnel Termination) — FedRAMP Moderate.
# On termination of individual employment, information-system access must be
# disabled within an organisation-defined time period (FedRAMP Moderate: same
# business day / within hours). This is directly observable from the identity
# provider, so Concord queries the IdP for every user marked SUSPENDED,
# DEPROVISIONED, or DELETED in the lookback window and verifies each terminated
# user has no active session, no active application assignments, and no admin
# role memberships, and that access was revoked inside the required window.

# FedRAMP Moderate expects prompt revocation on termination; 24 hours is the
# operational floor enforced here.
max_revocation_window_hours := 24

deny contains msg if {
	not input.okta_terminations
	msg := "FedRAMP PS-4: no identity-provider termination evidence collected"
}

deny contains msg if {
	some user in input.okta_terminations.users
	user.has_active_session
	msg := sprintf("FedRAMP PS-4: terminated user %q still has an active session", [user.email])
}

deny contains msg if {
	some user in input.okta_terminations.users
	count(user.active_application_assignments) > 0
	msg := sprintf("FedRAMP PS-4: terminated user %q still has %d active application assignment(s)", [user.email, count(user.active_application_assignments)])
}

deny contains msg if {
	some user in input.okta_terminations.users
	count(user.admin_role_memberships) > 0
	msg := sprintf("FedRAMP PS-4: terminated user %q still has admin role(s): %v", [user.email, user.admin_role_memberships])
}

deny contains msg if {
	some user in input.okta_terminations.users
	user.revocation_lag_hours > max_revocation_window_hours
	msg := sprintf("FedRAMP PS-4: terminated user %q access was revoked %d hours after termination (FedRAMP Moderate floor is %d)", [user.email, user.revocation_lag_hours, max_revocation_window_hours])
}

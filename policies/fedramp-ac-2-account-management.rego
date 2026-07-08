package concord.fedramp.account_management

import rego.v1

# NIST SP 800-53 Rev 5 AC-2 (Account Management) / FedRAMP Moderate.
# Concord reads the AWS IAM credential-report inventory and fails accounts that
# break the account-management lifecycle: accounts left active after being
# disabled, accounts inactive beyond the FedRAMP 90-day threshold (AC-2(3)),
# and accounts with no owner tag to attribute responsibility.
# Evidence: input.iam_credential_report.users[].

# FedRAMP Moderate AC-2(3) requires disabling accounts after 90 days of
# inactivity. An explicit day-count keeps the check time-independent.
max_inactive_days := 90

# Fail closed: without a credential report, account management is unproven.
deny contains msg if {
	not input.iam_credential_report
	msg := "no IAM credential report collected — cannot demonstrate account management (NIST 800-53 AC-2 / FedRAMP Moderate)"
}

# Disabled account that still holds a working credential.
deny contains msg if {
	some u in input.iam_credential_report.users
	u.enabled == false
	account_active(u)
	msg := sprintf("account %q is disabled but still holds an active credential — disabled accounts must have all access removed (NIST 800-53 AC-2 / FedRAMP Moderate)", [u.user])
}

# Console account inactive beyond the 90-day threshold.
deny contains msg if {
	some u in input.iam_credential_report.users
	u.user != "<root_account>"
	u.password_enabled == true
	is_number(u.password_last_used_days_ago)
	u.password_last_used_days_ago > max_inactive_days
	msg := sprintf("account %q last signed in %d days ago, exceeding the %d-day inactivity threshold — stale accounts must be disabled (NIST 800-53 AC-2(3) / FedRAMP Moderate)", [u.user, u.password_last_used_days_ago, max_inactive_days])
}

# Active access key unused beyond the 90-day threshold.
deny contains msg if {
	some u in input.iam_credential_report.users
	some k in u.access_keys
	k.active == true
	is_number(k.last_used_days_ago)
	k.last_used_days_ago > max_inactive_days
	msg := sprintf("account %q has an active access key unused for %d days, exceeding the %d-day inactivity threshold — stale credentials must be deactivated (NIST 800-53 AC-2(3) / FedRAMP Moderate)", [u.user, k.last_used_days_ago, max_inactive_days])
}

# Account with no owner tag cannot be attributed to a responsible party.
deny contains msg if {
	some u in input.iam_credential_report.users
	u.user != "<root_account>"
	not has_owner(u)
	msg := sprintf("account %q has no owner tag — every account must have an assigned owner for account management (NIST 800-53 AC-2 / FedRAMP Moderate)", [u.user])
}

account_active(u) if u.password_enabled == true

account_active(u) if {
	some k in u.access_keys
	k.active == true
}

has_owner(u) if {
	u.tags.owner
	u.tags.owner != ""
}

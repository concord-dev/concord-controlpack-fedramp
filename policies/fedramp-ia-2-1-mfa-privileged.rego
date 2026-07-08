package concord.fedramp.ia_2_1_mfa_privileged

import rego.v1

# NIST 800-53 Rev 5 IA-2(1) / FedRAMP Moderate — multi-factor authentication
# for access to privileged accounts. Evidence: AWS IAM credential report
# (input.iam_credentials.users[]). Adapted from HIPAA §164.312(d) and PCI DSS
# 8.6. A principal is privileged if it is root, is flagged admin, carries a
# privileged tag, or holds an admin-grade attached policy; where no explicit
# signal exists a console user that also holds an active long-lived access key
# is treated as privileged. Fail-closed via `not u.mfa_active`: false, null, or
# absent all count as no MFA.

# Attached policy name that grants broad administrative privilege.
admin_policy(name) if contains(lower(name), "admin")

admin_policy(name) if contains(lower(name), "poweruser")

is_privileged(u) if u.user == "<root_account>"

is_privileged(u) if u.admin == true

is_privileged(u) if u.tags.privileged == "true"

is_privileged(u) if {
	some p in u.attached_policies
	admin_policy(p)
}

# Fallback signal: a console identity that also holds an active access key is
# treated as privileged when no explicit admin marker is present.
is_privileged(u) if {
	u.password_enabled == true
	some k in u.access_keys
	k.active == true
}

# Fail closed: no credential report means privileged MFA cannot be proven.
deny contains msg if {
	not input.iam_credentials
	msg := "no IAM credential report collected — cannot verify MFA on privileged accounts (NIST 800-53 IA-2(1) / FedRAMP Moderate)"
}

# Privileged console identity without an active MFA device.
deny contains msg if {
	some u in input.iam_credentials.users
	u.password_enabled == true
	is_privileged(u)
	not u.mfa_active
	msg := sprintf("privileged IAM user %q has console access without an active MFA device (NIST 800-53 IA-2(1) / FedRAMP Moderate)", [u.user])
}

package concord.fedramp.ia_2_2_mfa_non_privileged

import rego.v1

# NIST 800-53 Rev 5 IA-2(2) / FedRAMP Moderate — multi-factor authentication
# for access to non-privileged accounts. Evidence: AWS IAM credential report
# (input.iam_credentials.users[]). Adapted from HIPAA §164.312(d)
# (person_or_entity_authentication). Every IAM user with console (password)
# access must have an active MFA device; root is covered by IA-2(1) and is
# surfaced here only as an advisory. Fail-closed via `not u.mfa_active`.

# Fail closed: no credential report means MFA coverage cannot be proven.
deny contains msg if {
	not input.iam_credentials
	msg := "no IAM credential report collected — cannot verify MFA on console users (NIST 800-53 IA-2(2) / FedRAMP Moderate)"
}

# Console-enabled non-root identity without an active MFA device.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user != "<root_account>"
	u.password_enabled == true
	not u.mfa_active
	msg := sprintf("IAM user %q has console access without an active MFA device (NIST 800-53 IA-2(2) / FedRAMP Moderate)", [u.user])
}

# Root MFA is enforced by IA-2(1); advise here if root is console-enabled
# without MFA rather than duplicating the failure.
warn contains msg if {
	some u in input.iam_credentials.users
	u.user == "<root_account>"
	u.password_enabled == true
	not u.mfa_active
	msg := "root account has console access without MFA — enable a hardware MFA device on root (NIST 800-53 IA-2(1))"
}

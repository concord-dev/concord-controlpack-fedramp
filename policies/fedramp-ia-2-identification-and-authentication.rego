package concord.fedramp.ia_2_identification

import rego.v1

# NIST 800-53 Rev 5 IA-2 / FedRAMP Moderate — organizational users must be
# uniquely identified and authenticated so that actions are traceable to a
# known individual. Evidence: AWS IAM credential report
# (input.iam_credentials.users[]). Adapted from PCI DSS 8.1
# (concord.pci_dss.user_identification). Fails shared/generic console accounts
# and routine use of the root account.

# Names that indicate a shared, group, or generic (non-individual) account.
generic_patterns := {
	"admin",
	"administrator",
	"shared",
	"service",
	"svc",
	"generic",
	"team",
	"group",
	"operator",
	"guest",
}

# Root is treated as "used routinely" when its console password was used within
# this window (days). An explicit day-count keeps the check time-independent.
routine_use_days := 30

is_generic(name) if {
	some pattern in generic_patterns
	contains(lower(name), pattern)
}

# Fail closed: no credential report means uniqueness cannot be demonstrated.
deny contains msg if {
	not input.iam_credentials
	msg := "no IAM credential report collected — cannot demonstrate that every user is uniquely identified (NIST 800-53 IA-2 / FedRAMP Moderate)"
}

# Console-enabled account with a shared/generic name.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user != "<root_account>"
	u.password_enabled == true
	is_generic(u.user)
	msg := sprintf("IAM user %q has a shared/generic name with console access — access must be tied to a unique, named individual (NIST 800-53 IA-2 / FedRAMP Moderate)", [u.user])
}

# Root account used for routine console operations.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user == "<root_account>"
	u.password_enabled == true
	u.password_last_used_days_ago <= routine_use_days
	msg := sprintf("root account was used %d day(s) ago — root must not be used for routine operations, which breaks unique identification (NIST 800-53 IA-2 / FedRAMP Moderate)", [u.password_last_used_days_ago])
}

# Root account holding a long-lived programmatic credential.
deny contains msg if {
	some u in input.iam_credentials.users
	u.user == "<root_account>"
	some k in u.access_keys
	k.active == true
	msg := "root account has an active access key — root must have no standing credentials and must not be used routinely (NIST 800-53 IA-2 / FedRAMP Moderate)"
}

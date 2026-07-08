package concord.fedramp.ia_5_authenticator

import rego.v1

# NIST 800-53 Rev 5 IA-5 / IA-5(1) / FedRAMP Moderate — Authenticator
# Management. The AWS IAM account password policy must enforce minimum length,
# character complexity, rotation, and reuse-prevention. Evidence: AWS IAM
# account password policy (input.password_policy). Adapted from CIS AWS 1.16
# (concord.cis_aws.iam_password_policy) with FedRAMP Moderate thresholds.
# Fail-closed: an absent or unconfigured policy denies.

min_length := 12

max_age_days := 60

reuse_prevention := 24

# Fail closed: no evidence means the authenticator policy cannot be shown.
deny contains msg if {
	not input.password_policy
	msg := "no IAM password policy evidence collected (NIST 800-53 IA-5 / FedRAMP Moderate)"
}

# Fail closed: no account password policy is configured at all.
deny contains msg if {
	input.password_policy.configured == false
	msg := "no IAM account password policy is configured — IA-5(1) requires one (FedRAMP Moderate)"
}

deny contains msg if {
	p := input.password_policy.policy
	p.minimum_password_length < min_length
	msg := sprintf("minimum_password_length is %d, must be >= %d (NIST 800-53 IA-5(1) / FedRAMP Moderate)", [p.minimum_password_length, min_length])
}

deny contains msg if {
	p := input.password_policy.policy
	p.require_symbols == false
	msg := "require_symbols is false — IA-5(1) requires symbol complexity (FedRAMP Moderate)"
}

deny contains msg if {
	p := input.password_policy.policy
	p.require_numbers == false
	msg := "require_numbers is false — IA-5(1) requires digit complexity (FedRAMP Moderate)"
}

deny contains msg if {
	p := input.password_policy.policy
	p.require_uppercase_characters == false
	msg := "require_uppercase_characters is false — IA-5(1) requires uppercase complexity (FedRAMP Moderate)"
}

deny contains msg if {
	p := input.password_policy.policy
	p.require_lowercase_characters == false
	msg := "require_lowercase_characters is false — IA-5(1) requires lowercase complexity (FedRAMP Moderate)"
}

deny contains msg if {
	p := input.password_policy.policy
	p.expire_passwords == false
	msg := sprintf("expire_passwords is false; max_password_age must be set to <= %d days (NIST 800-53 IA-5(1) / FedRAMP Moderate)", [max_age_days])
}

deny contains msg if {
	p := input.password_policy.policy
	p.expire_passwords == true
	p.max_password_age > max_age_days
	msg := sprintf("max_password_age is %d, must be <= %d days (NIST 800-53 IA-5(1) / FedRAMP Moderate)", [p.max_password_age, max_age_days])
}

deny contains msg if {
	p := input.password_policy.policy
	p.password_reuse_prevention < reuse_prevention
	msg := sprintf("password_reuse_prevention is %d, must remember >= %d previous passwords (NIST 800-53 IA-5(1) / FedRAMP Moderate)", [p.password_reuse_prevention, reuse_prevention])
}

warn contains msg if {
	p := input.password_policy.policy
	p.allow_users_to_change_password == false
	msg := "users cannot change their own passwords — required for rotation hygiene (NIST 800-53 IA-5)"
}

package concord.fedramp.least_privilege

import rego.v1

# NIST SP 800-53 Rev 5 AC-6 (Least Privilege) / FedRAMP Moderate.
# The organization must employ the principle of least privilege, allowing only
# the authorizations necessary to accomplish assigned tasks. Concord reads every
# IAM identity (user, group, and role) with its attached managed and inline
# policies and fails any identity that carries a standing full-admin grant: the
# AWS-managed AdministratorAccess policy or a statement allowing Action "*" on
# Resource "*". Such a grant is broader than any single job function requires.
# Evidence: input.iam_policies.identities[].attached_policies[].

# Fail closed: without policy evidence least privilege cannot be demonstrated.
deny contains msg if {
	not input.iam_policies
	msg := "no IAM policy evidence collected — cannot demonstrate least privilege (NIST 800-53 AC-6 / FedRAMP Moderate)"
}

# Attached to the AWS-managed AdministratorAccess policy.
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	p.policy_name == "AdministratorAccess"
	msg := sprintf("IAM %s %q is attached to AdministratorAccess — standing full-admin access is broader than least privilege permits (NIST 800-53 AC-6 / FedRAMP Moderate)", [identity_type(id), id.name])
}

# Attached to any policy that allows Action "*" on Resource "*".
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	some stmt in p.document.Statement
	stmt.Effect == "Allow"
	action_is_wildcard(stmt)
	resource_is_wildcard(stmt)
	msg := sprintf("IAM %s %q attaches policy %q allowing Action \"*\" on Resource \"*\" — the grant exceeds the privileges any job function requires (NIST 800-53 AC-6 / FedRAMP Moderate)", [identity_type(id), id.name, p.policy_name])
}

identity_type(id) := id.type

identity_type(id) := "identity" if not id.type

action_is_wildcard(stmt) if stmt.Action == "*"

action_is_wildcard(stmt) if {
	some a in stmt.Action
	a == "*"
}

resource_is_wildcard(stmt) if stmt.Resource == "*"

resource_is_wildcard(stmt) if {
	some r in stmt.Resource
	r == "*"
}

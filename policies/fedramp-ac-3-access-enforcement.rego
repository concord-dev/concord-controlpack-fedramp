package concord.fedramp.access_enforcement

import rego.v1

# NIST SP 800-53 Rev 5 AC-3 (Access Enforcement) / FedRAMP Moderate.
# The system must enforce approved authorizations for logical access, which in
# AWS IAM depends on a deny-by-default posture. Concord inspects the effect
# statements of every attached IAM policy and fails any statement that subverts
# deny-by-default: an Allow of Action "*" on Resource "*" (an explicit
# allow-all), or an Allow that uses NotAction or NotResource, which inverts the
# model into "allow everything except" and re-opens the default-deny baseline.
# Evidence: input.iam_policies.identities[].attached_policies[].document.Statement[].

# Fail closed: without policy evidence the enforcement posture is unproven.
deny contains msg if {
	not input.iam_policies
	msg := "no IAM policy evidence collected — cannot verify access enforcement defaults to deny-all (NIST 800-53 AC-3 / FedRAMP Moderate)"
}

# Explicit allow-all statement contradicts enforcement of approved authorizations.
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	some stmt in p.document.Statement
	stmt.Effect == "Allow"
	action_is_wildcard(stmt)
	resource_is_wildcard(stmt)
	msg := sprintf("IAM %s %q policy %q allows Action \"*\" on Resource \"*\" — an explicit allow-all defeats enforcement of approved authorizations (NIST 800-53 AC-3 / FedRAMP Moderate)", [identity_type(id), id.name, p.policy_name])
}

# Allow + NotAction inverts the model to "allow every action except ..." and
# therefore fails open, re-opening the default-deny baseline.
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	some stmt in p.document.Statement
	stmt.Effect == "Allow"
	stmt.NotAction
	msg := sprintf("IAM %s %q policy %q uses Allow + NotAction — this allows every action except a deny-list and subverts deny-by-default access enforcement (NIST 800-53 AC-3 / FedRAMP Moderate)", [identity_type(id), id.name, p.policy_name])
}

# Allow + NotResource inverts the model to "allow on every resource except ..."
# and likewise fails open for any new resource.
deny contains msg if {
	some id in input.iam_policies.identities
	some p in id.attached_policies
	some stmt in p.document.Statement
	stmt.Effect == "Allow"
	stmt.NotResource
	msg := sprintf("IAM %s %q policy %q uses Allow + NotResource — this allows access to every resource except a deny-list and subverts deny-by-default access enforcement (NIST 800-53 AC-3 / FedRAMP Moderate)", [identity_type(id), id.name, p.policy_name])
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

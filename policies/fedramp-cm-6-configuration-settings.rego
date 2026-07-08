package concord.fedramp.cm_6_config_settings

import rego.v1

# NIST 800-53 Rev 5 CM-6 / FedRAMP Moderate — mandatory configuration settings
# must be established and enforced for system components. In AWS this is proven
# by benchmark-aligned Config conformance packs: at least one benchmark pack
# (FedRAMP or CIS) must be deployed and every deployed pack must report
# COMPLIANT. Evidence: AWS Config conformance pack status
# (input.config_conformance). Adapted from PCI DSS 2.2.1. Fail-closed: absent
# evidence, no benchmark pack, or a non-COMPLIANT pack denies.

benchmark_pack(name) if contains(lower(name), "fedramp")

benchmark_pack(name) if contains(lower(name), "cis")

# Fail closed: no evidence means enforced settings cannot be demonstrated.
deny contains msg if {
	not input.config_conformance
	msg := "no AWS Config conformance evidence collected — cannot demonstrate enforced configuration settings (NIST 800-53 CM-6 / FedRAMP Moderate)"
}

# No conformance pack deployed at all.
deny contains msg if {
	input.config_conformance
	count(object.get(input.config_conformance, "conformance_packs", [])) == 0
	msg := "no Config conformance pack is deployed to enforce configuration settings (NIST 800-53 CM-6 / FedRAMP Moderate)"
}

# Packs exist but none is benchmark-aligned.
deny contains msg if {
	input.config_conformance
	count(object.get(input.config_conformance, "conformance_packs", [])) > 0
	not any_benchmark_pack
	msg := "no benchmark-aligned Config conformance pack (FedRAMP or CIS) is deployed to enforce configuration settings (NIST 800-53 CM-6 / FedRAMP Moderate)"
}

# Any deployed pack that is not COMPLIANT (fail-closed on absent state).
deny contains msg if {
	some pack in input.config_conformance.conformance_packs
	not pack.compliance_state == "COMPLIANT"
	msg := sprintf("Config conformance pack %q is %q (expected COMPLIANT) (NIST 800-53 CM-6 / FedRAMP Moderate)", [pack.name, object.get(pack, "compliance_state", "UNKNOWN")])
}

any_benchmark_pack if {
	some pack in input.config_conformance.conformance_packs
	benchmark_pack(pack.name)
}

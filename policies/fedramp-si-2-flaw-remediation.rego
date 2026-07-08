package concord.fedramp.si_2

import rego.v1

# NIST 800-53 Rev 5 SI-2 (Flaw Remediation) / FedRAMP Moderate — security
# flaws must be corrected within the FedRAMP-defined window (30 days for
# high-risk findings). Read from AWS SSM Patch Manager. Fail-closed: an
# instance is denied unless it explicitly reports a COMPLIANT patch state, and
# any missing critical/security patch older than 30 days is denied per instance.
#
# Reused from concord-controlpack-pci-dss pci_dss_6_2_patch_management.
# Evidence: input.patch_compliance.instances.

max_patch_age_days := 30

deny contains msg if {
	not input.patch_compliance
	msg := "SI-2: no SSM patch-compliance evidence collected"
}

deny contains msg if {
	some instance in input.patch_compliance.instances
	not instance.compliance_status == "COMPLIANT"
	msg := sprintf("SI-2: instance %q reports patch-compliance status %q (expected COMPLIANT) (NIST 800-53 SI-2 / FedRAMP Moderate)", [instance.instance_id, object.get(instance, "compliance_status", "UNKNOWN")])
}

deny contains msg if {
	some instance in input.patch_compliance.instances
	instance.oldest_missing_critical_age_days > max_patch_age_days
	msg := sprintf("SI-2: instance %q has a missing critical/security patch %d days old, exceeding the %d-day FedRAMP SLA (NIST 800-53 SI-2)", [instance.instance_id, instance.oldest_missing_critical_age_days, max_patch_age_days])
}

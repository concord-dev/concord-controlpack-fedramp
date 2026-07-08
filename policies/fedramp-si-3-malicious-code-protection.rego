package concord.fedramp.si_3

import rego.v1

# NIST 800-53 Rev 5 SI-3 (Malicious Code Protection) / FedRAMP Moderate —
# malicious-code protection must be employed across the estate. Concord
# verifies AWS GuardDuty has an enabled detector in every active region and
# that Amazon Inspector is enabled at the account level. Fails closed when no
# evidence is collected, a region lacks a detector, or Inspector is disabled.
#
# Reused from concord-controlpack-pci-dss r_5_2 (anti-malware coverage).
# Evidence: input.malware_protection.{active_regions,guardduty_detectors,inspector_account_enabled}.

deny contains msg if {
	not input.malware_protection
	msg := "SI-3: no malicious-code-protection evidence collected"
}

deny contains msg if {
	some region in input.malware_protection.active_regions
	not has_guardduty(region)
	msg := sprintf("SI-3: GuardDuty malicious-code detection is not enabled in active region %q (NIST 800-53 SI-3 / FedRAMP Moderate)", [region])
}

deny contains msg if {
	not input.malware_protection.inspector_account_enabled
	msg := "SI-3: Amazon Inspector is not enabled at the account level; workloads and images are not scanned for malicious code (NIST 800-53 SI-3 / FedRAMP Moderate)"
}

has_guardduty(region) if {
	some d in input.malware_protection.guardduty_detectors
	d.region == region
	d.status == "ENABLED"
}

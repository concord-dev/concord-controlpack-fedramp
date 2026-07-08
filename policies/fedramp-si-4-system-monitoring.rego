package concord.fedramp.si_4

import rego.v1

# NIST 800-53 Rev 5 SI-4 (System Monitoring) / FedRAMP Moderate — the system
# must be monitored to detect attacks and indicators of potential attacks.
# Concord verifies AWS GuardDuty has an enabled detector in every active
# region and fails closed when no evidence or no active region is reported.
#
# Reused from concord-controlpack-pci-dss r_11_4 (intrusion detection).
# Evidence: input.system_monitoring.{active_regions,guardduty_detectors}.

deny contains msg if {
	not input.system_monitoring
	msg := "SI-4: no system-monitoring evidence collected"
}

deny contains msg if {
	input.system_monitoring
	count(input.system_monitoring.active_regions) == 0
	msg := "SI-4: no active regions reported; system-monitoring coverage cannot be verified — failing closed (NIST 800-53 SI-4 / FedRAMP Moderate)"
}

deny contains msg if {
	some region in input.system_monitoring.active_regions
	not has_enabled_detector(region)
	msg := sprintf("SI-4: GuardDuty system monitoring is not enabled in active region %q (NIST 800-53 SI-4 / FedRAMP Moderate)", [region])
}

has_enabled_detector(region) if {
	some d in input.system_monitoring.guardduty_detectors
	d.region == region
	d.status == "ENABLED"
}

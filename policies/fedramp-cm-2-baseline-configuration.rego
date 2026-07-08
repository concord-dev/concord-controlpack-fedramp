package concord.fedramp.cm_2_baseline

import rego.v1

# NIST 800-53 Rev 5 CM-2 / FedRAMP Moderate — a current baseline configuration
# of the system must be maintained. In AWS this means the Config recorder is
# enabled and recording in every active region so the configuration of all
# resources is continuously captured. Evidence: AWS Config recorder status
# (input.config_recorders). Adapted from PCI DSS 2.2.1
# (concord.pci_dss.pci_dss_2_2_1_system_configuration_standards). Fail-closed:
# absent evidence, no active regions, or a non-recording region denies.

# Fail closed: no evidence means a maintained baseline cannot be demonstrated.
deny contains msg if {
	not input.config_recorders
	msg := "no AWS Config recorder evidence collected — cannot demonstrate a maintained baseline configuration (NIST 800-53 CM-2 / FedRAMP Moderate)"
}

# Fail closed: evidence present but no active regions enumerated.
deny contains msg if {
	input.config_recorders
	count(object.get(input.config_recorders, "active_regions", [])) == 0
	msg := "no active regions reported — cannot demonstrate baseline configuration recording (NIST 800-53 CM-2 / FedRAMP Moderate)"
}

# Any active region without a recording Config recorder.
deny contains msg if {
	some region in input.config_recorders.active_regions
	not has_recording_in_region(region)
	msg := sprintf("AWS Config recorder is not recording in active region %q — baseline configuration is not captured there (NIST 800-53 CM-2 / FedRAMP Moderate)", [region])
}

has_recording_in_region(region) if {
	some recorder in input.config_recorders.recorders
	recorder.region == region
	recorder.recording == true
}

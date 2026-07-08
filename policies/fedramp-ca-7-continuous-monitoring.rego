package concord.fedramp.ca_7_continuous_monitoring

import rego.v1

# NIST 800-53 Rev 5 CA-7 / FedRAMP Moderate — Continuous Monitoring.
# CA-7 requires an ongoing monitoring capability that maintains situational
# awareness of the security posture across the authorization boundary. Concord
# proves this technically in AWS: the AWS Config recorder must be continuously
# recording in every active region (ongoing configuration/state monitoring),
# and Amazon GuardDuty must be enabled in every active region (ongoing threat
# detection). The evidence is delivered bare under input.continuous_monitoring.
# Fail-closed: missing evidence, no enumerated regions, a stopped recorder, or
# a disabled detector all deny.

# Fail closed: no evidence collected at all.
deny contains msg if {
	not input.continuous_monitoring
	msg := "FedRAMP CA-7: no AWS continuous-monitoring evidence collected — monitoring cannot be verified (fail closed)"
}

# Fail closed: the inventory must enumerate the active regions it covers.
deny contains msg if {
	input.continuous_monitoring
	count(object.get(input.continuous_monitoring, "active_regions", [])) == 0
	msg := "FedRAMP CA-7: no active regions reported — continuous-monitoring coverage cannot be verified (fail closed)"
}

# Configuration monitoring: the AWS Config recorder must be recording in every
# active region so configuration drift is captured continuously.
deny contains msg if {
	some region in input.continuous_monitoring.active_regions
	not config_recording_in_region(region)
	msg := sprintf("FedRAMP CA-7: AWS Config recorder is not continuously recording in active region %q — configuration changes go unmonitored", [region])
}

# Threat monitoring: Amazon GuardDuty must be enabled in every active region so
# threats and anomalous activity are detected continuously.
deny contains msg if {
	some region in input.continuous_monitoring.active_regions
	not guardduty_enabled_in_region(region)
	msg := sprintf("FedRAMP CA-7: Amazon GuardDuty is not enabled in active region %q — threats are not continuously monitored", [region])
}

config_recording_in_region(region) if {
	some r in input.continuous_monitoring.recorders
	r.region == region
	r.recording == true
}

guardduty_enabled_in_region(region) if {
	some d in input.continuous_monitoring.guardduty_detectors
	d.region == region
	d.status == "ENABLED"
}

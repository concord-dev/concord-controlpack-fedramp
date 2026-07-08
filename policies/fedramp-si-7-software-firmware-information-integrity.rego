package concord.fedramp.si_7

import rego.v1

# NIST 800-53 Rev 5 SI-7 (Software, Firmware, and Information Integrity) with
# SI-7(1) integrity checks / FedRAMP Moderate — integrity verification tools
# must detect unauthorized changes. Concord verifies CloudTrail log-file
# validation (tamper-evident audit records) and AWS Config drift detection
# (continuous configuration recording). Fails closed when evidence, trails, or
# an active Config recorder are missing.
#
# Reused from concord-controlpack-nist-800-53 cloudtrail_multi_region and
# concord-controlpack-hipaa integrity. Evidence:
# input.integrity_monitoring.{trails,config_recorders}.

deny contains msg if {
	not input.integrity_monitoring
	msg := "SI-7: no integrity-monitoring evidence collected"
}

# Fail closed: no CloudTrail trail means no tamper-evident audit record exists.
deny contains msg if {
	input.integrity_monitoring
	count(input.integrity_monitoring.trails) == 0
	msg := "SI-7: no CloudTrail trail exists; log-file integrity validation cannot be verified — failing closed (NIST 800-53 SI-7(1) / FedRAMP Moderate)"
}

# Every trail must have log-file integrity validation enabled.
deny contains msg if {
	some trail in input.integrity_monitoring.trails
	not trail.log_file_validation_enabled == true
	msg := sprintf("SI-7: CloudTrail trail %q does not have log-file integrity validation enabled; tampering with audit records would go undetected (NIST 800-53 SI-7(1) / FedRAMP Moderate)", [trail.name])
}

# Fail closed: AWS Config drift detection must be present.
deny contains msg if {
	input.integrity_monitoring
	count(input.integrity_monitoring.config_recorders) == 0
	msg := "SI-7: no AWS Config recorder exists; unauthorized configuration drift cannot be detected — failing closed (NIST 800-53 SI-7 / FedRAMP Moderate)"
}

# Config recorder must actually be recording.
deny contains msg if {
	some rec in input.integrity_monitoring.config_recorders
	not rec.recording == true
	msg := sprintf("SI-7: AWS Config recorder %q is not recording; configuration-drift detection is off (NIST 800-53 SI-7 / FedRAMP Moderate)", [rec.name])
}

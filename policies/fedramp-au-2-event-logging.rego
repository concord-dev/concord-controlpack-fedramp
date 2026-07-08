package concord.fedramp.au_2

import rego.v1

# NIST 800-53 AU-2 (Event Logging) / FedRAMP Moderate — the system must log the
# event categories the organisation has determined to be auditable. Concord
# verifies that AWS CloudTrail records management events for both read and write
# activity and captures at least one data-event selector so data-plane access is
# logged. Each missing category denies independently; fail closed when no
# evidence is present.

trails := input.cloudtrail_events.trails

deny contains msg if {
	not input.cloudtrail_events
	msg := "no CloudTrail event-selector evidence collected"
}

deny contains msg if {
	input.cloudtrail_events
	not mgmt_read_logged
	msg := "CloudTrail is not logging management (control-plane) read events; privileged read activity is not captured (NIST 800-53 AU-2 / FedRAMP Moderate)"
}

deny contains msg if {
	input.cloudtrail_events
	not mgmt_write_logged
	msg := "CloudTrail is not logging management (control-plane) write events; privileged change activity is not captured (NIST 800-53 AU-2 / FedRAMP Moderate)"
}

deny contains msg if {
	input.cloudtrail_events
	not data_events_logged
	msg := "CloudTrail has no data-event selector; data-plane access to stored information is not captured (NIST 800-53 AU-2 / FedRAMP Moderate)"
}

mgmt_read_logged if {
	some trail in trails
	some sel in trail.event_selectors
	sel.include_management_events == true
	sel.read_write_type in {"All", "ReadOnly"}
}

mgmt_write_logged if {
	some trail in trails
	some sel in trail.event_selectors
	sel.include_management_events == true
	sel.read_write_type in {"All", "WriteOnly"}
}

data_events_logged if {
	some trail in trails
	some sel in trail.event_selectors
	count(sel.data_resources) > 0
}

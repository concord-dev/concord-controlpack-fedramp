package concord.fedramp.fedramp_cp_9_system_backup

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "fedramp_cp_9_system_backup")
	msg := "FEDRAMP-CP-9-system-backup: aws evidence missing"
}

deny contains msg if {
	some r in input.fedramp_cp_9_system_backup.resources
	not r.compliant
	msg := sprintf("FEDRAMP-CP-9-system-backup: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}

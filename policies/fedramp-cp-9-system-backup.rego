package concord.fedramp.cp_9

import rego.v1

# NIST SP 800-53 Rev 5 CP-9 (System Backup) and CP-9(1) (Testing for
# Reliability and Integrity), FedRAMP Moderate. Evidence is collected via the
# aws backup_status collector. Concord verifies that every in-scope data store
# (tagged fedramp="true") has automated backups at a FedRAMP-grade retention
# floor, that DynamoDB point-in-time recovery is enabled, and that AWS Backup
# vaults holding in-scope data are vault-locked and have been restore-tested
# within the last year.
# Adapted from Prowler: rds_instance_backup_enabled,
# dynamodb_tables_pitr_enabled, backup_vaults_encrypted_with_kms_cmk.

min_retention_days := 30

max_restore_test_age_days := 365

deny contains msg if {
	not input.system_backups
	msg := "FEDRAMP CP-9: no backup evidence collected"
}

deny contains msg if {
	some rds in input.system_backups.rds_instances
	in_scope(rds)
	rds.backup_retention_period < min_retention_days
	msg := sprintf("FEDRAMP CP-9: in-scope RDS instance %q has backup retention %d days (FedRAMP Moderate floor is %d)", [rds.identifier, rds.backup_retention_period, min_retention_days])
}

deny contains msg if {
	some table in input.system_backups.dynamodb_tables
	in_scope(table)
	not table.point_in_time_recovery_enabled
	msg := sprintf("FEDRAMP CP-9: in-scope DynamoDB table %q has point-in-time recovery disabled", [table.name])
}

deny contains msg if {
	some vault in input.system_backups.backup_vaults
	vault.holds_in_scope_data
	not vault.locked
	msg := sprintf("FEDRAMP CP-9: backup vault %q holds in-scope data but is not vault-locked (tamper-resistant retention required)", [vault.name])
}

# CP-9(1): backups must be tested. A vault holding in-scope data whose most
# recent successful restore test is older than a year (or which has never been
# tested) is a finding.
deny contains msg if {
	some vault in input.system_backups.backup_vaults
	vault.holds_in_scope_data
	not restore_tested_recently(vault)
	msg := sprintf("FEDRAMP CP-9(1): backup vault %q has not had a successful restore test in the last %d days (restore_test_age_days=%v)", [vault.name, max_restore_test_age_days, object.get(vault, "restore_test_age_days", "never")])
}

restore_tested_recently(vault) if {
	vault.restore_test_age_days <= max_restore_test_age_days
}

in_scope(resource) if {
	resource.tags.fedramp == "true"
}

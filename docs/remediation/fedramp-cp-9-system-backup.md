# In-scope data stores have automated, tamper-resistant, tested backups

`FEDRAMP-CP-9-system-backup` · framework **fedramp** · severity **critical** · Contingency Planning

## What this control checks

NIST SP 800-53 Rev 5 CP-9 (System Backup), with enhancement CP-9(1)
(Testing for Reliability and Integrity), requires the organization to
conduct backups of user-level and system-level information at defined
frequencies and to test backup information to verify recovery. Concord
verifies that every in-scope data store (tagged fedramp="true") has
automated backups enabled with a FedRAMP-grade retention floor, that
point-in-time recovery is enabled for DynamoDB, and that AWS Backup vaults
holding in-scope data are vault-locked for tamper-resistance and have had a
successful restore test within the last year.

## Why it matters

Backups are the last line of defense against ransomware, accidental
deletion, and silent corruption, but only if they are automated, retained
long enough to outlast a slow-burn compromise, protected from tampering,
and actually restorable. Ransomware crews routinely delete or encrypt the
backups first, so CP-9 pairs automated backups with vault locking, and
CP-9(1) demands proof that a restore has been exercised, because an
untested backup is a hypothesis, not a recovery capability. Concord reads
the live AWS backup posture so this is verified continuously rather than
asserted once at authorization.

## Evidence

Collected from the `aws` source (`backup_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FEDRAMP CP-9: no backup evidence collected
- FEDRAMP CP-9: in-scope RDS instance <value> has backup retention <value> days (FedRAMP Moderate floor is <value>)
- FEDRAMP CP-9: in-scope DynamoDB table <value> has point-in-time recovery disabled
- FEDRAMP CP-9: backup vault <value> holds in-scope data but is not vault-locked (tamper-resistant retention required)
- FEDRAMP CP-9(1): backup vault <value> has not had a successful restore test in the last <value> days (restore_test_age_days=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **4h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-CP-9-system-backup
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "CP-9"
  - "CP-9(1)"
  soc2:
  - "A1.2"
  iso27001:
  - "A.8.13"
  hipaa:
  - "164.308(a)(7)(ii)(A)"
```

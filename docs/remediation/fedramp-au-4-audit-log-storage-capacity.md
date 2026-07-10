# System allocates adequate audit log storage capacity

`FEDRAMP-AU-4-audit-log-storage-capacity` · framework **fedramp** · severity **medium** · Audit and Accountability

## What this control checks

NIST 800-53 AU-4 (Audit Log Storage Capacity), as required by the FedRAMP
Moderate baseline, requires the system to allocate audit log storage
capacity sufficient to retain records for the organisation-defined period
and to reduce the likelihood of storage being exceeded. Concord verifies
that every audit-log CloudWatch log group has an explicit retention period
at or above the organisation-defined floor and that any S3 lifecycle rule
used for long-term overflow storage does not expire records earlier than
that floor. Each log group below the threshold is reported separately, and
the check fails closed when no storage-capacity mechanism is configured at
all.

## Why it matters

Audit records are only useful if the system reserves enough storage to keep
them for the period reviewers and investigators need. A CloudWatch log group
with a short or missing retention window silently deletes history and can
also let unbounded ingestion pressure other workloads, while an S3 lifecycle
rule that expires objects too early quietly discards the archived overflow.
Requiring an explicit retention floor on every audit log group, plus a
lifecycle policy on any archive bucket, demonstrates that capacity has been
deliberately planned rather than left to default. Concord fails closed when
no capacity mechanism exists, because an unmanaged log store cannot be shown
to satisfy AU-4.

## Evidence

Collected from the `aws` source (`log_retention_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no audit-log storage-capacity evidence collected
- no audit-log storage capacity is allocated (neither CloudWatch log-group retention nor an S3 lifecycle rule); failing closed (NIST 800-53 AU-4 / FedRAMP Moderate)
- audit log group <value> reserves only <value> days of retention, below the organisation-defined minimum of <value> days (NIST 800-53 AU-4 / FedRAMP Moderate)
- S3 audit-log archive bucket <value> expires objects after <value> days, below the organisation-defined minimum of <value> days (NIST 800-53 AU-4 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AU-4-audit-log-storage-capacity
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53: ["AU-4", "AU-11"]
  pci_dss: ["10.7", "10.5.1"]
  soc2: ["CC7.2"]
  cis_aws: ["3.4"]
```

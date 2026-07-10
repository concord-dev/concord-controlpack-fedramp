# Maintenance and repair on system components are controlled and recorded

`FEDRAMP-MA-2-controlled-maintenance` · framework **fedramp** · severity **medium** · Maintenance

## What this control checks

NIST SP 800-53 Rev 5 control MA-2 (Controlled Maintenance), required at the
FedRAMP Moderate baseline, requires the organisation to schedule, document,
and review records of maintenance, repair, and replacement of system
components, and to sanitise equipment of any information before it is removed
from the facility for off-site maintenance. Off-site maintenance and the
surrounding approval and record-keeping are physical and procedural
activities that are not observable through cloud telemetry, so Concord reads
a signed, version-controlled attestation of the controlled-maintenance
program from the repository and confirms it declares an approval process, a
records-retention period, explicit confirmation that media is sanitised
before off-site maintenance, and a recent signed review.

## Why it matters

Maintenance is a classic side-door into an authorised system: a technician
with physical access, a replaced-but-not-wiped drive shipped back to a
vendor, or a repair performed with no record all bypass the logical controls
that the rest of the baseline depends on. A maintenance procedure kept as a
slide deck silently goes stale, so Concord anchors the evidence to a
git-versioned attestation whose freshness, off-site sanitisation commitment,
and signature are verified on every run — turning "we control maintenance"
into "the maintenance program is current, sanitises media before it leaves,
and is approved".

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP MA-2: no controlled-maintenance attestation evidence collected
- FedRAMP MA-2: no controlled-maintenance attestation document found at the configured repository path
- FedRAMP MA-2: controlled-maintenance attestation <value> is missing required field <value>
- FedRAMP MA-2: controlled-maintenance attestation <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- FedRAMP MA-2: controlled-maintenance attestation <value> does not confirm media sanitisation before off-site maintenance (sanitisation_before_offsite=<value>)
- FedRAMP MA-2: controlled-maintenance attestation <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-MA-2-controlled-maintenance
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "MA-2"
  iso27001:
  - "A.7.13"
  soc2:
  - "CC6.5"
```

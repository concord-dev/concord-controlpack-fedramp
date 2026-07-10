# Integrity verification tools detect unauthorised changes

`FEDRAMP-SI-7-software-firmware-information-integrity` · framework **fedramp** · severity **medium** · System and Information Integrity

## What this control checks

NIST 800-53 Rev 5 SI-7 (Software, Firmware, and Information Integrity),
with enhancement SI-7(1) (Integrity Checks), as required by the FedRAMP
Moderate baseline, requires the organization to employ integrity
verification tools to detect unauthorized changes to software, firmware,
and information. Concord verifies the two AWS mechanisms that provide this
assurance: every CloudTrail trail must have log-file integrity validation
enabled (so tampering with the audit record is detectable), and AWS Config
must have an active recorder (so unauthorized configuration drift is
detected). A trail without log-file validation, or a Config recorder that
is not recording, fails the control.

## Why it matters

Integrity controls are only meaningful if the record used to detect
tampering is itself tamper-evident: CloudTrail log-file validation produces
digitally signed digests so that any modification or deletion of audit logs
is detectable, and AWS Config continuously records resource configuration so
that drift from the approved baseline is caught rather than discovered after
an incident. FedRAMP treats both as the technical implementation of SI-7's
integrity-verification requirement. The check fails closed: missing
evidence, no trails, a trail without validation, or a stopped Config
recorder each deny rather than pass.

## Evidence

Collected from the `aws` source (`integrity_monitoring` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- SI-7: no integrity-monitoring evidence collected
- SI-7: no CloudTrail trail exists; log-file integrity validation cannot be verified — failing closed (NIST 800-53 SI-7(1) / FedRAMP Moderate)
- SI-7: CloudTrail trail <value> does not have log-file integrity validation enabled; tampering with audit records would go undetected (NIST 800-53 SI-7(1) / FedRAMP Moderate)
- SI-7: no AWS Config recorder exists; unauthorized configuration drift cannot be detected — failing closed (NIST 800-53 SI-7 / FedRAMP Moderate)
- SI-7: AWS Config recorder <value> is not recording; configuration-drift detection is off (NIST 800-53 SI-7 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-SI-7-software-firmware-information-integrity
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "SI-7"
  - "SI-7(1)"
  - "AU-9"
  hipaa:
  - "164.312(c)(1)"
  soc2:
  - "CC7.1"
```

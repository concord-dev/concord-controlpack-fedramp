# Confidentiality and integrity of information at rest are protected

`FEDRAMP-SC-28-protection-of-information-at-rest` · framework **fedramp** · severity **critical** · System and Communications Protection

## What this control checks

NIST 800-53 Rev 5 SC-28 (Protection of Information at Rest), with
enhancement SC-28(1) (Cryptographic Protection), as required by the FedRAMP
Moderate baseline, requires the system to protect the confidentiality and
integrity of information at rest. Concord verifies that every data store in
the authorization boundary has encryption-at-rest enabled: S3 buckets, RDS
instances, and EBS volumes must each report an active encryption
configuration. Any store without encryption-at-rest is reported
individually.

## Why it matters

Encryption-at-rest is the primary safeguard against disclosure of federal
information from lost media, snapshot exfiltration, or misconfigured storage
access, and unencrypted storage is one of the most common and highest-impact
findings during a FedRAMP assessment. Evaluating S3, RDS, and EBS separately
and per-resource means a single unencrypted bucket or volume fails the
control rather than being masked by an otherwise-encrypted estate, and the
fail-closed default treats a store with no reported encryption state as
non-compliant.

## Evidence

Collected from the `aws` source (`storage_encryption` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- SC-28: no encryption-at-rest evidence collected
- SC-28: S3 bucket <value> has no encryption-at-rest configured (NIST 800-53 SC-28 / FedRAMP Moderate)
- SC-28: RDS instance <value> has no encryption-at-rest configured (NIST 800-53 SC-28 / FedRAMP Moderate)
- SC-28: EBS volume <value> has no encryption-at-rest configured (NIST 800-53 SC-28 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-SC-28-protection-of-information-at-rest
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "SC-28"
  - "SC-28(1)"
  hipaa:
  - "164.312(a)(2)(iv)"
  soc2:
  - "CC6.1"
```

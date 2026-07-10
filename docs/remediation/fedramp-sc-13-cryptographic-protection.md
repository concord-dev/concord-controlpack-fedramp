# FIPS-validated cryptographic mechanisms protect information

`FEDRAMP-SC-13-cryptographic-protection` · framework **fedramp** · severity **critical** · System and Communications Protection

## What this control checks

NIST 800-53 Rev 5 SC-13 (Cryptographic Protection), as required by the
FedRAMP Moderate baseline, requires that cryptography used to protect
information implements FIPS-validated or NSA-approved mechanisms. Concord
verifies this technically against AWS data stores and the KMS keys that
protect them: every S3 bucket and RDS instance must be encrypted with a
customer-managed KMS key (SSE-S3 / AES256 alone is insufficient because it
does not use a FIPS-validated, controllable key), and any KMS key that is
explicitly signalled as not FIPS 140-2/140-3 validated is denied.

## Why it matters

FedRAMP mandates FIPS 140-validated cryptographic modules wherever
cryptography is used to protect federal information; the mere presence of
encryption is not sufficient if the underlying module or key is not
validated. Requiring a customer-managed KMS key rather than bucket-default
AES256 ensures the key material lives in AWS KMS FIPS-validated HSMs and is
subject to access control, rotation, and audit. The check evaluates each
data store individually and fails closed: an unencrypted store, an AES256
store, or a key flagged fips_validated=false each fails on its own rather
than being averaged away across a healthy estate.

## Evidence

Collected from the `aws` source (`storage_encryption` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- SC-13: no cryptographic-protection evidence collected
- SC-13: S3 bucket <value> has no server-side encryption configured (NIST 800-53 SC-13 / FedRAMP Moderate)
- SC-13: S3 bucket <value> uses AES256 (SSE-S3); FedRAMP requires a FIPS-validated customer-managed KMS key (NIST 800-53 SC-13)
- SC-13: RDS instance <value> has no encryption-at-rest configured (NIST 800-53 SC-13 / FedRAMP Moderate)
- SC-13: KMS key <value> is not FIPS 140-validated; only FIPS-validated cryptographic modules may protect federal information (NIST 800-53 SC-13 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-SC-13-cryptographic-protection
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "SC-13"
  - "SC-28(1)"
  pci_dss:
  - "3.4"
  - "3.5"
  soc2:
  - "CC6.1"
```

# Audit information and audit tools are protected from unauthorised access

`FEDRAMP-AU-9-protection-of-audit-information` · framework **fedramp** · severity **high** · Audit and Accountability

## What this control checks

NIST 800-53 AU-9 (Protection of Audit Information), as required by the
FedRAMP Moderate baseline, requires audit information and audit logging
tools to be protected from unauthorised access, modification, and deletion.
Concord verifies that every logging CloudTrail trail has log-file validation
enabled so records are tamper-evident, is encrypted at rest with a KMS key
so audit data cannot be read by unauthorised parties, and stores its logs in
an S3 bucket that is not publicly accessible so access is restricted. Each
unprotected trail is reported separately, and the check fails closed when no
trail is present.

## Why it matters

Audit records are the primary evidence used to detect and investigate
misuse, which makes them a prime target for an attacker seeking to cover
their tracks. Log-file validation lets any post-hoc modification or deletion
of CloudTrail records be detected; KMS encryption ensures the log contents
are unreadable without an authorised key; and a non-public log bucket
prevents both exfiltration and tampering by anonymous principals. A trail
that is missing any of these protections leaves audit information exposed to
exactly the manipulation AU-9 is meant to prevent, so Concord fails closed
when no trail is present and denies per trail for each missing safeguard.

## Evidence

Collected from the `aws` source (`audit_trail_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudTrail evidence collected
- no CloudTrail trail present; audit information cannot be shown to be protected — failing closed (NIST 800-53 AU-9 / FedRAMP Moderate)
- CloudTrail trail <value> has log-file validation disabled; audit records are not protected from undetected modification (NIST 800-53 AU-9 / FedRAMP Moderate)
- CloudTrail trail <value> is not encrypted with a KMS key; audit information is not protected at rest (NIST 800-53 AU-9 / FedRAMP Moderate)
- CloudTrail trail <value> stores logs in a publicly accessible S3 bucket; access to audit information is not restricted (NIST 800-53 AU-9 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AU-9-protection-of-audit-information
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53: ["AU-9", "AU-9(2)", "AU-9(3)"]
  pci_dss: ["10.3.2", "10.5.1"]
  hipaa: ["164.312(b)", "164.312(c)(1)"]
  soc2: ["CC7.2"]
  cis_aws: ["3.2", "3.7"]
```

# MFA is enforced for privileged accounts

`FEDRAMP-IA-2-1-mfa-privileged` · framework **fedramp** · severity **critical** · Identification and Authentication

## What this control checks

NIST 800-53 Rev 5 IA-2(1) (Multi-factor Authentication to Privileged
Accounts), required by the FedRAMP Moderate baseline, requires multi-factor
authentication for network access to privileged accounts. Concord reads the
AWS IAM credential report and denies any privileged, console-enabled
identity that has no active MFA device. An identity is treated as
privileged when it is the root account, is flagged admin, carries a tag
privileged=true, or holds an admin-grade attached policy (for example
AdministratorAccess or PowerUserAccess); where no explicit signal exists, a
console user that also holds an active long-lived access key is treated as
privileged. Missing or false mfa_active is treated as no MFA so the control
never fails open.

## Why it matters

Privileged accounts are the highest-value target in any environment: a
single compromised administrator credential can disable logging, exfiltrate
data, and pivot across the whole system, so IA-2(1) singles them out for a
mandatory second factor. Password-only privileged access is repeatedly the
root cause in cloud breach reports. By resolving privilege from explicit
admin markers, admin-grade policies, and — as a fallback — active access
keys on console identities, Concord surfaces every privileged path lacking
MFA. The check fails closed: an mfa_active value that is false, null, or
absent denies, and an absent credential report denies outright.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected — cannot verify MFA on privileged accounts (NIST 800-53 IA-2(1) / FedRAMP Moderate)
- privileged IAM user <value> has console access without an active MFA device (NIST 800-53 IA-2(1) / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-IA-2-1-mfa-privileged
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "IA-2(1)"
  pci_dss:
  - "8.6"
  - "8.4.2"
  hipaa:
  - "164.312(d)"
  cis_aws:
  - "1.10"
```

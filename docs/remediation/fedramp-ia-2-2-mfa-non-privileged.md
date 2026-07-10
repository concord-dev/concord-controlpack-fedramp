# MFA is enforced for non-privileged accounts

`FEDRAMP-IA-2-2-mfa-non-privileged` · framework **fedramp** · severity **high** · Identification and Authentication

## What this control checks

NIST 800-53 Rev 5 IA-2(2) (Multi-factor Authentication to Non-privileged
Accounts), required by the FedRAMP Moderate baseline, requires multi-factor
authentication for network access to non-privileged accounts. Concord reads
the AWS IAM credential report and denies every IAM user with console
(password) access that has no active MFA device. The root account is
evaluated by IA-2(1) and is surfaced here only as an advisory. Missing or
false mfa_active is treated as no MFA so the control never fails open.

## Why it matters

Non-privileged interactive accounts are the broadest slice of the user
population and the most common initial-access vector: single-factor console
logins are routinely phished or credential-stuffed, and once inside an
attacker can escalate. IA-2(2) therefore extends the second-factor
requirement beyond administrators to every human who can sign in. Enforcing
an active MFA device on all console identities is the highest-leverage
authentication safeguard and a prerequisite for meaningful access logging.
The check fails closed — an absent credential report denies rather than
assuming coverage.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected — cannot verify MFA on console users (NIST 800-53 IA-2(2) / FedRAMP Moderate)
- IAM user <value> has console access without an active MFA device (NIST 800-53 IA-2(2) / FedRAMP Moderate)
- root account has console access without MFA — enable a hardware MFA device on root (NIST 800-53 IA-2(1))

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-IA-2-2-mfa-non-privileged
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "IA-2(2)"
  hipaa:
  - "164.312(d)"
  cis_aws:
  - "1.10"
```

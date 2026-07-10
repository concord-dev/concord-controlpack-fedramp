# Organisational users are uniquely identified and authenticated

`FEDRAMP-IA-2-identification-and-authentication` · framework **fedramp** · severity **critical** · Identification and Authentication

## What this control checks

NIST 800-53 Rev 5 IA-2 (Identification and Authentication — Organizational
Users), required by the FedRAMP Moderate baseline, requires the system to
uniquely identify and authenticate each organizational user and to
associate that unique identity with every action for accountability.
Concord reads the AWS IAM credential report and fails any console-enabled
identity whose name matches a shared or generic pattern (for example
"admin", "shared", "service"), because such accounts cannot attribute
activity to one individual. It also fails routine use of the root account —
recent console sign-in or a standing access key — because day-to-day use of
the unnamed root principal breaks unique identification.

## Why it matters

Shared and generic logins are the classic way individual accountability
collapses: when several administrators sign in as "admin", no audit record
can place a specific person at a specific action, defeating IA-2 and the AU
audit-trail controls at once. The root account carries the same problem
plus unlimited privilege, so it must be reserved for the rare tasks that
genuinely require it rather than routine work. The control fails closed — if
the credential report is absent it denies rather than assuming every
identity is unique.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected — cannot demonstrate that every user is uniquely identified (NIST 800-53 IA-2 / FedRAMP Moderate)
- IAM user <value> has a shared/generic name with console access — access must be tied to a unique, named individual (NIST 800-53 IA-2 / FedRAMP Moderate)
- root account was used <value> day(s) ago — root must not be used for routine operations, which breaks unique identification (NIST 800-53 IA-2 / FedRAMP Moderate)
- root account has an active access key — root must have no standing credentials and must not be used routinely (NIST 800-53 IA-2 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-IA-2-identification-and-authentication
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "IA-2"
  - "AC-2"
  pci_dss:
  - "8.1"
  - "8.2.1"
  cis_aws:
  - "1.7"
```

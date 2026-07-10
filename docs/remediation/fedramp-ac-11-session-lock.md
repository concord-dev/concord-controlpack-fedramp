# System initiates session lock after defined idle period

`FEDRAMP-AC-11-session-lock` · framework **fedramp** · severity **low** · Access Control

## What this control checks

NIST SP 800-53 Rev 5 AC-11 (Session Lock), as required by the FedRAMP
Moderate baseline, requires the system to initiate a session lock after a
defined period of inactivity; FedRAMP parameterizes that period at 15
minutes. For interactive AWS access (the Management Console and IAM Identity
Center) the enforcing control is the configured idle-lock timeout. Concord
fails any IAM role scoped to interactive human use whose configured idle
session-lock timeout exceeds 900 seconds, and fails closed on any
interactive role that publishes no idle-lock setting at all.

## Why it matters

A console or Identity Center session left open on an unattended workstation
is a direct exposure of the system to anyone with physical access; the
session lock is what closes that window without ending the session
outright. Roles are scoped to interactive use via the session_type tag so
that non-interactive service roles, which never hold a human session, are
not falsely flagged. The control fails closed: an interactive role with no
published idle-lock timeout is denied rather than assumed compliant, because
an unproven lock is indistinguishable from no lock at all.

## Evidence

Collected from the `aws` source (`iam_roles` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM role evidence collected — cannot verify session lock on inactivity (NIST 800-53 AC-11 / FedRAMP Moderate)
- interactive role <value> publishes no idle session-lock timeout — session lock on inactivity cannot be verified (NIST 800-53 AC-11 / FedRAMP Moderate)
- interactive role <value> allows <value> seconds of inactivity before session lock, exceeding the <value>-second (15-minute) threshold (NIST 800-53 AC-11 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **4h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AC-11-session-lock
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "AC-11"
  - "AC-11(1)"
  soc2:
  - "CC6.1"
  hipaa:
  - "164.312(a)(2)(iii)"
```

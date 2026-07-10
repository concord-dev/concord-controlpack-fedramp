# System automatically terminates a session after defined conditions

`FEDRAMP-AC-12-session-termination` · framework **fedramp** · severity **medium** · Access Control

## What this control checks

NIST SP 800-53 Rev 5 AC-12 (Session Termination), as required by the FedRAMP
Moderate baseline, requires the system to automatically terminate a user
session after organization-defined conditions or trigger events. For
federated and assumed AWS access, the hard ceiling on a session is the
role's MaxSessionDuration: once it elapses the session ends and
re-authentication is required. Concord fails any IAM role scoped to
interactive human use whose max_session_duration_seconds exceeds the
3600-second (one-hour) threshold, and fails closed on any interactive role
that does not publish a max session duration.

## Why it matters

Long-lived assumed sessions are a recurring FedRAMP finding because they
defeat automatic termination: a session opened once can persist for the AWS
maximum of twelve hours, long after the operator has walked away or a role
should have been revoked. Bounding interactive roles to one hour forces
periodic re-authentication and keeps the effective session aligned with
AC-12. Roles are scoped to interactive use via the session_type tag so
service roles are not falsely flagged. The control fails closed: an
interactive role with no published ceiling is denied rather than assumed to
terminate.

## Evidence

Collected from the `aws` source (`iam_roles` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM role evidence collected — cannot verify automatic session termination (NIST 800-53 AC-12 / FedRAMP Moderate)
- interactive role <value> does not publish a max session duration — automatic session termination cannot be verified (NIST 800-53 AC-12 / FedRAMP Moderate)
- interactive role <value> allows sessions of <value> seconds, exceeding the <value>-second (one-hour) automatic-termination threshold (NIST 800-53 AC-12 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **4h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AC-12-session-termination
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "AC-12"
  soc2:
  - "CC6.1"
  hipaa:
  - "164.312(a)(2)(iii)"
```

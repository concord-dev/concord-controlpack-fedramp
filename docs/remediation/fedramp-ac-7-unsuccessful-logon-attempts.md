# System limits consecutive invalid login attempts and locks the account

`FEDRAMP-AC-7-unsuccessful-logon-attempts` · framework **fedramp** · severity **medium** · Access Control

## What this control checks

NIST SP 800-53 Rev 5 AC-7 (Unsuccessful Logon Attempts), as required by the
FedRAMP Moderate baseline, requires enforcing a limit on consecutive invalid
logon attempts and taking a defined action when that limit is exceeded.
Because the AWS Management Console does not natively lock accounts, the
compensating detective control is a CloudWatch Logs metric filter over the
CloudTrail log group that matches failed console authentications, wired to a
CloudWatch alarm with an active notification action. Concord fails the
control when no metric filter matches failed ConsoleLogin events, or when a
matching filter's metric has no alarm with an enabled notification action.

## Why it matters

Repeated failed console log-ins are the clearest early signal of
credential-stuffing and brute-force attacks against accounts inside the
authorization boundary. Without a metric filter and alarm the failures are
buried in CloudTrail and no one is paged, so the response AC-7 mandates when
the invalid-attempt limit is exceeded never happens. FedRAMP assessors
routinely ask for proof of the alarm and its notification target, mirroring
CIS AWS Foundations 3.6. The control fails closed: with no CloudWatch
evidence it denies rather than assuming failed logons are watched.

## Evidence

Collected from the `aws` source (`cloudwatch_alarms` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudWatch metric-filter/alarm evidence collected — cannot verify repeated failed logons are detected (NIST 800-53 AC-7 / FedRAMP Moderate)
- no CloudWatch metric filter matches failed console log-ins (ConsoleLogin + "Failed authentication") — repeated invalid logon attempts cannot be detected (NIST 800-53 AC-7 / FedRAMP Moderate)
- metric filter <value> matches failed console log-ins but its metric has no CloudWatch alarm with an enabled notification action — nobody is alerted when the invalid-logon limit is exceeded (NIST 800-53 AC-7 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **4h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AC-7-unsuccessful-logon-attempts
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "AC-7"
  soc2:
  - "CC6.1"
  - "CC7.2"
  hipaa:
  - "164.308(a)(5)(ii)(C)"
```

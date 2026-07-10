# Account management procedures cover provisioning, monitoring, and removal

`FEDRAMP-AC-2-account-management` · framework **fedramp** · severity **critical** · Access Control

## What this control checks

NIST SP 800-53 Rev 5 AC-2 (Account Management), as required by the FedRAMP
Moderate baseline, requires the organization to manage system accounts
across their full lifecycle: creation, activation, monitoring for
inactivity, and disabling or removal. Concord reads the AWS IAM
credential-report inventory and fails any account that breaks that
lifecycle: an account that is marked disabled yet still holds a working
credential, a console account or active access key that has been inactive
beyond the FedRAMP 90-day threshold (AC-2(3)), or an account carrying no
owner tag to attribute responsibility.

## Why it matters

Dormant and orphaned accounts are among the most common footholds in a
FedRAMP environment: a contractor account that is "disabled" in a ticket
but still authenticates, an access key untouched for a year, or an account
with no named owner all defeat the monitoring and removal that AC-2
demands. FedRAMP Moderate specifically parameterizes AC-2(3) to disable
accounts after 90 days of inactivity, so the check enforces that window
directly. It fails closed: when no credential report is collected it denies
rather than assuming every account is properly managed.

## Evidence

Collected from the `aws` source (`iam_credential_report` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM credential report collected — cannot demonstrate account management (NIST 800-53 AC-2 / FedRAMP Moderate)
- account <value> is disabled but still holds an active credential — disabled accounts must have all access removed (NIST 800-53 AC-2 / FedRAMP Moderate)
- account <value> last signed in <value> days ago, exceeding the <value>-day inactivity threshold — stale accounts must be disabled (NIST 800-53 AC-2(3) / FedRAMP Moderate)
- account <value> has an active access key unused for <value> days, exceeding the <value>-day inactivity threshold — stale credentials must be deactivated (NIST 800-53 AC-2(3) / FedRAMP Moderate)
- account <value> has no owner tag — every account must have an assigned owner for account management (NIST 800-53 AC-2 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AC-2-account-management
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "AC-2"
  - "AC-2(3)"
  soc2:
  - "CC6.1"
  - "CC6.2"
  - "CC6.3"
  pci_dss:
  - "8.1"
```

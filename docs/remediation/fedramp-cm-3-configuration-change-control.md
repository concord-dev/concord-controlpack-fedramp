# Configuration changes are tracked, reviewed, approved, and reversible

`FEDRAMP-CM-3-configuration-change-control` · framework **fedramp** · severity **medium** · Configuration Management

## What this control checks

NIST 800-53 Rev 5 CM-3 (FedRAMP Moderate) requires changes to the system
to be proposed and documented, reviewed and approved or disapproved with
explicit consideration of security impact, tested before implementation,
and to have a documented means of backing the change out. Concord reads
the version-controlled change-control procedure from the repository and
confirms it declares the change-approval process, the pre-implementation
testing requirement, and the rollback procedure, that it was reviewed
within the last year, and that it carries a verified signature.

## Why it matters

Unmanaged change is one of the most common causes of both outages and
security regressions: an unreviewed change can weaken a control, and a
change with no rollback plan turns a bad deploy into an incident. CM-3
exists to force security-impact review, testing, and reversibility into
the change path. Anchoring the check to a git-versioned, signed procedure
lets Concord confirm on every run that the approval process, testing gate,
and rollback plan are documented and current, rather than trusting that a
change board operates the way a slide once claimed.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP CM-3: no configuration-change-control evidence collected
- FedRAMP CM-3: no change-control document found at the configured repository path
- FedRAMP CM-3: change-control procedure <value> is missing required field <value>
- FedRAMP CM-3: change-control procedure <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- FedRAMP CM-3: change-control procedure <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-CM-3-configuration-change-control
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "CM-3"
  - "CM-4"
  soc2:
  - "CC8.1"
  iso27001:
  - "A.8.32"
```

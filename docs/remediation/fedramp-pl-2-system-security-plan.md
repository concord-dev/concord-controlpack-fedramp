# System security plan is documented, reviewed, and updated

`FEDRAMP-PL-2-system-security-plan` · framework **fedramp** · severity **high** · Planning

## What this control checks

NIST SP 800-53 Rev 5 control PL-2 (System Security Plan), required at the
FedRAMP Moderate baseline, requires the organisation to develop, document,
and periodically review a system security plan (SSP) that defines the
authorisation boundary, describes how each control in the baseline is
implemented, and identifies the individuals and roles responsible for the
system. Concord reads the version-controlled SSP metadata from the repository
and confirms it declares the system boundary, a control-implementation
summary, the responsible roles, and a recent signed review.

## Why it matters

The SSP is the spine of a FedRAMP authorisation: it is the single document
the authorising official and 3PAO read to understand what is in scope and how
every other control is satisfied. An SSP that has drifted from reality — a
boundary that no longer matches the deployed architecture, an implementation
statement describing a control that was since removed — invalidates the
authorisation basis even when the underlying controls are sound. Concord
anchors the SSP to a git-versioned document whose freshness and signature are
verified on every run, so a plan that was written once for the audit and
never revisited fails rather than passing on paper.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP PL-2: no system-security-plan evidence collected
- FedRAMP PL-2: no system-security-plan document found at the configured repository path
- FedRAMP PL-2: system-security-plan <value> is missing required field <value>
- FedRAMP PL-2: system-security-plan <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- FedRAMP PL-2: system-security-plan <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-PL-2-system-security-plan
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "PL-2"
  iso27001:
  - "A.5.1"
  soc2:
  - "CC1.2"
```

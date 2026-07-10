# A contingency plan with recovery objectives is current, signed, and tested

`FEDRAMP-CP-2-contingency-plan` · framework **fedramp** · severity **high** · Contingency Planning

## What this control checks

NIST SP 800-53 Rev 5 CP-2 (Contingency Plan) requires an information
system contingency plan that identifies essential missions and business
functions, recovery objectives, roles and responsibilities with assigned
contact information, and activation criteria, and requires the plan to be
reviewed and updated on a defined cadence. FedRAMP Moderate expects the
plan to be exercised (tested) at least annually. Concord reads the
version-controlled contingency plan from the repository and confirms it
declares the roles and responsibilities, the recovery objectives (RTO and
RPO), the activation criteria, a recent test, and a recent signed review.

## Why it matters

A contingency plan proves its worth only in the minutes after an outage,
when there is no time to work out who declares an incident, what "restored"
means, or how long the business can tolerate being down. CP-2 pairs the
written plan with hard recovery objectives (RTO/RPO) and requires it to be
tested, because a plan that has never been rehearsed usually fails on
first contact with a real disaster. Concord anchors the evidence to a
git-versioned plan whose review freshness, test freshness, and cosign
signature are all verified on every run, so an assessor sees the plan is
complete, current, exercised, and approved rather than merely on file.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FEDRAMP CP-2: no contingency-plan evidence collected
- FEDRAMP CP-2: no contingency-plan document found at the configured repository path
- FEDRAMP CP-2: contingency plan <value> is missing required field <value>
- FEDRAMP CP-2: contingency plan <value> was last reviewed <value> days ago (CP-2 expects review at least every <value> days)
- FEDRAMP CP-2: contingency plan <value> was last tested <value> days ago (CP-2 expects the plan to be exercised at least every <value> days)
- FEDRAMP CP-2: contingency plan <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-CP-2-contingency-plan
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "CP-2"
  soc2:
  - "A1.2"
  - "A1.3"
  - "CC7.5"
  iso27001:
  - "A.5.29"
  - "A.5.30"
```

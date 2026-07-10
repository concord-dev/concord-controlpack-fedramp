# System provides audit-record generation capability for all auditable events

`FEDRAMP-AU-12-audit-generation` · framework **fedramp** · severity **high** · Audit and Accountability

## What this control checks

NIST 800-53 AU-12 (Audit Record Generation), as required by the FedRAMP
Moderate baseline, requires the system to provide audit-record generation
capability for the defined auditable events at every in-scope component,
across the whole system boundary. Concord verifies that AWS CloudTrail is
configured with at least one multi-region trail that is actively logging, so
that every region and every account component generates audit records for
control-plane activity. A trail that is missing, single-region, or stopped
leaves parts of the boundary with no audit-generation capability, and the
check fails closed.

## Why it matters

AU-12 is what turns the abstract list of auditable events from AU-2 into an
actual, always-on generation capability that spans the entire deployment. A
single-region trail generates records for only one region and silently omits
activity everywhere else, while a stopped trail generates nothing at all.
A multi-region CloudTrail trail that is enabled and logging is the
account-wide mechanism that guarantees every management API call in every
region produces an attributable audit record, which is the precondition for
the review, protection, and retention controls that build on it. Concord
fails closed when no qualifying trail is present.

## Evidence

Collected from the `aws` source (`audit_trail_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no audit-trail evidence collected
- no CloudTrail trail is configured; the system generates no account-wide audit records (NIST 800-53 AU-12 / FedRAMP Moderate)
- no multi-region CloudTrail trail is both enabled and logging; audit-record generation does not cover every region (NIST 800-53 AU-12 / FedRAMP Moderate)
- multi-region CloudTrail trail <value> is not currently logging; audit-record generation is halted (NIST 800-53 AU-12 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AU-12-audit-generation
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53: ["AU-12", "AU-2", "AU-3"]
  pci_dss: ["10.1", "10.2.1"]
  soc2: ["CC7.2"]
  cis_aws: ["3.1"]
```

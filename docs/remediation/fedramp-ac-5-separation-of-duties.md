# Separation of duties is defined in a current, signed conflicting-roles matrix

`FEDRAMP-AC-5-separation-of-duties` · framework **fedramp** · severity **high** · Access Control

## What this control checks

NIST SP 800-53 Rev 5 AC-5 (Separation of Duties) requires the
organization to identify and document the duties of individuals that
require separation, and to define system access authorizations that
support that separation. FedRAMP Moderate expects a maintained
duties-to-roles matrix that names the sensitive functions, the roles that
must be kept mutually exclusive, and the process for reviewing the matrix.
Concord reads the version-controlled separation-of-duties matrix from the
repository and confirms it declares the duties matrix, the conflicting
roles that have been identified, the review process, and a recent signed
review.

## Why it matters

Separation of duties is what stops a single insider from both making and
approving a privileged change, or from both administering and reviewing
the audit log that would catch them. AC-5 is only as strong as the matrix
that defines it: if the conflicting-role pairs are undocumented or the
matrix has drifted from the actual Okta group assignments, toxic
combinations accumulate silently. Concord anchors the evidence to a
git-versioned matrix whose freshness and cosign signature are verified on
every run, so an assessor sees not just that duties are separated but that
the separation is documented, current, and approved.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FEDRAMP AC-5: no separation-of-duties matrix evidence collected
- FEDRAMP AC-5: no separation-of-duties matrix document found at the configured repository path
- FEDRAMP AC-5: separation-of-duties matrix <value> is missing required field <value>
- FEDRAMP AC-5: separation-of-duties matrix <value> was last reviewed <value> days ago (AC-5 expects review at least every <value> days)
- FEDRAMP AC-5: separation-of-duties matrix <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AC-5-separation-of-duties
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "AC-5"
  soc2:
  - "CC1.3"
  - "CC5.2"
  iso27001:
  - "A.5.3"
```

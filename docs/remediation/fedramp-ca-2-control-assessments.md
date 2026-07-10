# Security controls are periodically assessed for effectiveness

`FEDRAMP-CA-2-control-assessments` · framework **fedramp** · severity **high** · Assessment, Authorization, and Monitoring

## What this control checks

NIST 800-53 Rev 5 CA-2 (FedRAMP Moderate) requires the security and
privacy controls in the system to be assessed for effectiveness on an
organization-defined frequency, by a designated assessor, against a
defined scope, with the resulting findings documented and tracked. For
FedRAMP this is the annual assessment performed by an independent
Third-Party Assessment Organization (3PAO). Concord reads the
version-controlled control-assessment record from the repository and
confirms it names the assessor and scope, records the date controls were
last assessed and the status of findings, that the assessment is no older
than one year, and that it carries a verified signature.

## Why it matters

Implementing a control is not the same as demonstrating it works. CA-2 is
the discipline that periodically tests controls and feeds the gaps back
into remediation, and FedRAMP requires that testing to be independent and
annual. An assessment record without a named assessor, a defined scope,
or a current date is not credible audit evidence. Anchoring the check to
a git-versioned, signed record lets Concord verify freshness and
completeness on every run, ensuring the "controls are assessed" claim is
backed by a real, recent, attributable assessment rather than an
aspiration.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP CA-2: no control-assessment evidence collected
- FedRAMP CA-2: no control-assessment document found at the configured repository path
- FedRAMP CA-2: control assessment <value> is missing required field <value>
- FedRAMP CA-2: control assessment <value> was last performed more than <value> days ago (last_assessment_at=<value>)
- FedRAMP CA-2: control assessment <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-CA-2-control-assessments
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "CA-2"
  - "CA-2(1)"
  soc2:
  - "CC4.1"
  iso27001:
  - "A.5.35"
```

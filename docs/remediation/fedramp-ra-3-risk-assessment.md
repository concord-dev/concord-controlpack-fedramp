# Risk assessment is conducted, documented, and updated

`FEDRAMP-RA-3-risk-assessment` · framework **fedramp** · severity **high** · Risk Assessment

## What this control checks

NIST 800-53 Rev 5 RA-3 (FedRAMP Moderate) requires the organization to
conduct a risk assessment of the system, document its results, and update
it on a defined cadence and whenever significant changes occur. The
assessment artifact itself is auditable evidence, so Concord reads the
version-controlled risk-assessment document from the repository and
confirms it declares its methodology, its scope, the mechanism by which
findings are tracked, and the date it was last performed, that the
assessment is no older than one year, and that it carries a verified
signature.

## Why it matters

A risk assessment that lives in a slide deck or a stale wiki page
silently drifts out of date, and an undated or unsigned assessment
cannot be trusted as the basis for authorization decisions. Anchoring
the evidence to a git-versioned document lets Concord verify on every run
that the methodology and scope are declared, that findings feed a
tracking mechanism (the POA&M), that the assessment was refreshed within
the last year, and that it was approved — turning "we assess risk" into
proof that the current, signed assessment is genuinely current.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP RA-3: no risk-assessment evidence collected
- FedRAMP RA-3: no risk-assessment document found at the configured repository path
- FedRAMP RA-3: risk assessment <value> is missing required field <value>
- FedRAMP RA-3: risk assessment <value> was last performed more than <value> days ago (last_assessment_at=<value>)
- FedRAMP RA-3: risk assessment <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-RA-3-risk-assessment
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "RA-3"
  soc2:
  - "CC3.1"
  - "CC3.2"
  iso27001:
  - "A.5.5"
```

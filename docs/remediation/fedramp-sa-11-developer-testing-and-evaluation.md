# Developer security testing and evaluation is required and validated

`FEDRAMP-SA-11-developer-testing-and-evaluation` · framework **fedramp** · severity **medium** · System and Services Acquisition

## What this control checks

NIST 800-53 Rev 5 SA-11 (FedRAMP Moderate) requires the developer of the
system, component, or service to perform security testing and evaluation
at a defined frequency — for example static analysis (SAST), dynamic
analysis (DAST), and software composition / dependency analysis — and to
track and remediate the flaws that testing uncovers. Concord reads the
version-controlled developer-testing record from the repository and
confirms it declares the testing types performed, the frequency at which
they run, the date testing was last performed, and the flaw-remediation
tracking mechanism, that testing occurred within the last year, and that
it carries a verified signature.

## Why it matters

Security defects are cheapest to fix while software is still being built,
and SA-11 pushes assurance activities left into the development pipeline
instead of relying solely on a periodic external assessment. A testing
program that names no techniques, runs on no schedule, or never tracks
remediation is theatre. Anchoring the check to a git-versioned, signed
record lets Concord confirm on every run that SAST/DAST/SCA are declared,
running on a real cadence, recently exercised, and feeding a remediation
loop — evidence that developer testing is an operating practice rather
than a checkbox.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP SA-11: no developer-testing evidence collected
- FedRAMP SA-11: no developer-testing document found at the configured repository path
- FedRAMP SA-11: developer-testing record <value> is missing required field <value>
- FedRAMP SA-11: developer security testing <value> was last performed more than <value> days ago (last_performed_at=<value>)
- FedRAMP SA-11: developer-testing record <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-SA-11-developer-testing-and-evaluation
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "SA-11"
  - "SA-11(1)"
  soc2:
  - "CC8.1"
  iso27001:
  - "A.8.28"
  - "A.8.29"
```

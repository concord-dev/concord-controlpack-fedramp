# Media is sanitised prior to disposal, release, or reuse

`FEDRAMP-MP-6-media-sanitisation` · framework **fedramp** · severity **high** · Media Protection

## What this control checks

NIST SP 800-53 Rev 5 control MP-6 (Media Sanitization), required at the
FedRAMP Moderate baseline, requires the organisation to sanitise system media
prior to disposal, release out of organisational control, or reuse, using
sanitisation techniques and procedures consistent with NIST SP 800-88. Media
sanitisation is a physical and procedural activity that is not observable
through cloud telemetry, so Concord reads a signed, version-controlled
attestation of the sanitisation program from the repository and confirms it
declares a sanitisation method that is a NIST SP 800-88 approved technique
(clear, purge, destroy, or cryptographic erase), a verification process, and
a recent signed review.

## Why it matters

"Sanitisation" that is really a factory reset or a quick format leaves data
trivially recoverable, which is exactly the finding assessors look for and
exactly how retired drives end up leaking protected data on the resale
market. Naming a specific, recognised technique and requiring evidence that
the result is verified is what separates real destruction from a checkbox.
Concord validates the declared method against the NIST SP 800-88 categories
and anchors the evidence to a git-versioned attestation whose freshness and
signature are verified on every run, so an unapproved method or a stale,
unsigned policy fails rather than passing quietly.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP MP-6: no media-sanitisation attestation evidence collected
- FedRAMP MP-6: no media-sanitisation attestation document found at the configured repository path
- FedRAMP MP-6: media-sanitisation attestation <value> is missing required field <value>
- FedRAMP MP-6: media-sanitisation attestation <value> declares method <value>, which is not a NIST SP 800-88 approved technique (clear, purge, destroy, crypto_erase)
- FedRAMP MP-6: media-sanitisation attestation <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- FedRAMP MP-6: media-sanitisation attestation <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-MP-6-media-sanitisation
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "MP-6"
  hipaa:
  - "164.310(d)(2)(i)"
  iso27001:
  - "A.7.14"
  soc2:
  - "CC6.5"
```

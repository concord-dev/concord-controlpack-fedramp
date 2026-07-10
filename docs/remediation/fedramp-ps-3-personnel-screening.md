# Personnel are screened prior to authorising access

`FEDRAMP-PS-3-personnel-screening` · framework **fedramp** · severity **medium** · Personnel Security

## What this control checks

NIST SP 800-53 Rev 5 control PS-3 (Personnel Screening), required at the
FedRAMP Moderate baseline, requires the organisation to screen individuals
prior to authorising access to the system and to re-screen them according to
defined conditions and a defined cadence. Screening is an HR and procedural
activity that is not observable through cloud telemetry, so Concord reads a
signed, version-controlled attestation of the screening program from the
repository and confirms it declares the screening process, the positions in
scope, the re-screening cadence, and a recent signed review.

## Why it matters

Access control decides what an identity may do; screening decides whether the
person behind that identity should have been trusted with it in the first
place. Skipping background screening for a role with production access, or
letting a once-defined screening standard lapse as the organisation grows,
is the kind of gap that only surfaces after an insider incident. Concord
anchors the screening program to a git-versioned attestation that must name
the positions in scope and a re-screening cadence, and whose freshness and
signature are verified on every run, so an undocumented or stale program
fails rather than passing on paper.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP PS-3: no personnel-screening attestation evidence collected
- FedRAMP PS-3: no personnel-screening attestation document found at the configured repository path
- FedRAMP PS-3: personnel-screening attestation <value> is missing required field <value>
- FedRAMP PS-3: personnel-screening attestation <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- FedRAMP PS-3: personnel-screening attestation <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-PS-3-personnel-screening
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "PS-3"
  iso27001:
  - "A.6.1"
  soc2:
  - "CC1.4"
```

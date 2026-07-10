# System media is physically controlled and securely stored

`FEDRAMP-MP-4-media-storage` · framework **fedramp** · severity **medium** · Media Protection

## What this control checks

NIST SP 800-53 Rev 5 control MP-4 (Media Storage), required at the FedRAMP
Moderate baseline, requires the organisation to physically control and
securely store digital and non-digital media within controlled areas, and to
restrict access to that media to authorised personnel. Physical media
handling is not observable through cloud APIs, so Concord reads a signed,
version-controlled attestation of the media-storage program from the
repository and confirms it declares the storage controls in force, that a
media inventory is maintained, the access restrictions applied, and a recent
signed review.

## Why it matters

Media is a persistent blind spot even for cloud-first organisations: backup
tapes, removable drives, and printed system output all leave the reach of
logical access control the moment they are written. An uninventoried drive
in an unlocked cabinet is protected data walking out the door with nothing to
stop it. Assessors test MP-4 by asking to see the media inventory and the
controls over the room it lives in, so Concord anchors the evidence to a
git-versioned attestation whose freshness and signature are verified on every
run rather than accepting a policy that passes on paper.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP MP-4: no media-storage attestation evidence collected
- FedRAMP MP-4: no media-storage attestation document found at the configured repository path
- FedRAMP MP-4: media-storage attestation <value> is missing required field <value>
- FedRAMP MP-4: media-storage attestation <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- FedRAMP MP-4: media-storage attestation <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-MP-4-media-storage
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "MP-4"
  iso27001:
  - "A.7.10"
  soc2:
  - "CC6.4"
```

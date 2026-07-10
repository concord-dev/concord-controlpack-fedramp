# Physical access authorisations are enforced at access points

`FEDRAMP-PE-3-physical-access-control` · framework **fedramp** · severity **high** · Physical and Environmental Protection

## What this control checks

NIST SP 800-53 Rev 5 control PE-3 (Physical Access Control), required at the
FedRAMP Moderate baseline, requires the organisation to enforce physical
access authorisations at defined entry and exit points to facilities housing
the system — verifying individual access authorisations before granting
entry, controlling ingress and egress, and maintaining visitor access
records. Physical access enforcement is not observable through cloud APIs, so
Concord reads a signed, version-controlled attestation of the physical
access-control program from the repository and confirms it declares the
access-authorisation process, that access points are controlled, that
visitors are logged, and a recent signed review.

## Why it matters

Every logical control in the baseline assumes an attacker cannot simply walk
up to the hardware; PE-3 is the assumption made explicit. Tailgating through
an uncontrolled door or an unlogged visitor at the rack defeats access
enforcement, MFA, and encryption at rest in a single step. Assessors test
PE-3 against badge records and the visitor log, so Concord requires the
attestation to affirmatively confirm access points are controlled and
visitors are logged (explicit true, not merely mentioned) and anchors it to a
git-versioned document whose freshness and signature are verified on every
run.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP PE-3: no physical-access-control attestation evidence collected
- FedRAMP PE-3: no physical-access-control attestation document found at the configured repository path
- FedRAMP PE-3: physical-access-control attestation <value> is missing required field <value>
- FedRAMP PE-3: physical-access-control attestation <value> does not confirm access points are controlled (access_points_controlled=<value>)
- FedRAMP PE-3: physical-access-control attestation <value> does not confirm visitor access is logged (visitor_logging=<value>)
- FedRAMP PE-3: physical-access-control attestation <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- FedRAMP PE-3: physical-access-control attestation <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-PE-3-physical-access-control
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "PE-3"
  hipaa:
  - "164.310(a)(1)"
  iso27001:
  - "A.7.2"
  soc2:
  - "CC6.4"
```

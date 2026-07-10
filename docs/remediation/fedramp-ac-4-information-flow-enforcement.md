# Information flow between security zones is governed by a current, signed enforcement policy

`FEDRAMP-AC-4-information-flow-enforcement` · framework **fedramp** · severity **high** · Access Control

## What this control checks

NIST SP 800-53 Rev 5 AC-4 (Information Flow Enforcement) requires the
system to enforce approved authorizations for controlling the flow of
information within the system and between connected systems, based on
defined information flow control policies. FedRAMP Moderate mandates a
documented policy that identifies the security zones (authorization
boundary, data-classification tiers, DMZ/internal segments), the approved
flows between them, and the mechanisms that enforce those flows (security
groups, network ACLs, firewalls, gateways, proxies). Concord reads the
version-controlled flow-control policy from the repository and confirms it
declares the flow-control policy statement, the boundary/zone definitions,
the enforcement mechanisms, and a recent signed review.

## Why it matters

Information flow enforcement is the control that keeps a low-trust segment
from talking directly to a high-value data store; when it is undocumented
or stale, segmentation drifts and an attacker who lands in the DMZ reaches
the crown jewels unimpeded. FedRAMP assessors test AC-4 by reconciling the
documented approved flows against the actual boundary configuration, so a
policy that lives in a slide deck or has not been reviewed since the last
ATO is a finding. Concord anchors the evidence to a git-versioned document
whose freshness and cosign signature are verified on every run, turning
"we segment our network" into "the approved flows are documented, current,
and signed".

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FEDRAMP AC-4: no information-flow-enforcement policy evidence collected
- FEDRAMP AC-4: no information-flow-enforcement policy document found at the configured repository path
- FEDRAMP AC-4: flow-control policy <value> is missing required field <value>
- FEDRAMP AC-4: flow-control policy <value> was last reviewed <value> days ago (AC-4 expects review at least every <value> days)
- FEDRAMP AC-4: flow-control policy <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AC-4-information-flow-enforcement
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "AC-4"
  soc2:
  - "CC6.6"
  - "CC6.1"
  iso27001:
  - "A.8.22"
  - "A.8.23"
```

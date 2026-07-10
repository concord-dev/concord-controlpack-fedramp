# A documented incident response plan is current, signed, and tested

`FEDRAMP-IR-8-incident-response-plan` · framework **fedramp** · severity **high** · Incident Response

## What this control checks

NIST SP 800-53 Rev 5 IR-8 (Incident Response Plan) requires a documented
incident response plan that provides the organization with a roadmap for
implementing its incident response capability: the plan's scope, the
structure and roles of the incident response team, and how incident
response fits with the wider organization and external parties
(communication plan). FedRAMP Moderate expects the plan to be reviewed and
tested on a defined cadence. Concord reads the version-controlled incident
response plan from the repository and confirms it declares the plan scope,
the roles and responsibilities, the communication plan, a recent test, and
a recent signed review.

## Why it matters

IR-8 is the umbrella document that makes the rest of the IR family
coherent: without a plan that defines scope, team structure, and how the
organization communicates internally and to US-CERT, agency customers, and
the public, individual procedures fragment and responders improvise under
pressure. FedRAMP requires the plan to be exercised so gaps are found in a
tabletop rather than during a live breach. Concord anchors the evidence to
a git-versioned plan whose review freshness, exercise freshness, and cosign
signature are verified on every run, so an assessor sees the plan is
complete, current, tested, and approved.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FEDRAMP IR-8: no incident-response-plan evidence collected
- FEDRAMP IR-8: no incident-response-plan document found at the configured repository path
- FEDRAMP IR-8: incident response plan <value> is missing required field <value>
- FEDRAMP IR-8: incident response plan <value> was last reviewed <value> days ago (IR-8 expects review at least every <value> days)
- FEDRAMP IR-8: incident response plan <value> was last exercised <value> days ago (IR-8 expects testing at least every <value> days)
- FEDRAMP IR-8: incident response plan <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-IR-8-incident-response-plan
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "IR-8"
  soc2:
  - "CC7.3"
  - "CC7.4"
  - "CC7.5"
  iso27001:
  - "A.5.24"
  - "A.5.26"
```

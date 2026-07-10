# Incident handling capability is defined in a current, signed, tested procedure

`FEDRAMP-IR-4-incident-handling` · framework **fedramp** · severity **high** · Incident Response

## What this control checks

NIST SP 800-53 Rev 5 IR-4 (Incident Handling) requires an incident
handling capability that spans preparation, detection and analysis,
containment, eradication, and recovery, with defined roles and a feedback
loop into the wider control set. FedRAMP Moderate expects the capability to
be documented and exercised. Concord reads the version-controlled
incident-handling procedure from the repository and confirms it declares
the detection and analysis process, the containment and eradication
approach, the responder roles, a recent test, and a recent signed review.

## Why it matters

When an alert fires at 2 a.m., the difference between a contained event and
a reportable breach is whether responders know how to triage, contain, and
eradicate without destroying the forensic evidence they will later need.
IR-4 codifies that capability so it does not live only in one senior
engineer's head, and FedRAMP requires it to be tested so the muscle memory
exists before it is needed. Concord anchors the evidence to a git-versioned
procedure whose review freshness, exercise freshness, and cosign signature
are verified on every run, turning "we handle incidents" into a documented,
rehearsed, and approved capability.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FEDRAMP IR-4: no incident-handling procedure evidence collected
- FEDRAMP IR-4: no incident-handling procedure document found at the configured repository path
- FEDRAMP IR-4: incident-handling procedure <value> is missing required field <value>
- FEDRAMP IR-4: incident-handling procedure <value> was last reviewed <value> days ago (IR-4 expects review at least every <value> days)
- FEDRAMP IR-4: incident-handling procedure <value> was last exercised <value> days ago (IR-4 expects testing at least every <value> days)
- FEDRAMP IR-4: incident-handling procedure <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-IR-4-incident-handling
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "IR-4"
  soc2:
  - "CC7.3"
  - "CC7.4"
  iso27001:
  - "A.5.26"
  - "A.5.27"
```

# Incident reporting timeframes and authorities are defined in a current, signed procedure

`FEDRAMP-IR-6-incident-reporting` · framework **fedramp** · severity **high** · Incident Response

## What this control checks

NIST SP 800-53 Rev 5 IR-6 (Incident Reporting) requires personnel to
report suspected incidents within organization-defined time periods and to
report incident information to designated authorities. For FedRAMP this
includes reporting to US-CERT/CISA and to the authorizing official and
FedRAMP ISSO within the mandated timeframe (US-CERT requires reporting
within one hour of a confirmed incident). Concord reads the
version-controlled incident-reporting procedure from the repository and
confirms it declares the reporting timeframes, the authorities to be
notified (including US-CERT), the escalation path, and a recent signed
review.

## Why it matters

FedRAMP authorizations carry a hard external obligation that ordinary
corporate incident response does not: confirmed incidents must be reported
to US-CERT within one hour, and to the AO and FedRAMP PMO on their
timelines. Missing that window is itself a compliance failure independent
of how well the incident was handled technically. Codifying the exact
timeframes, named authorities, and escalation path removes the fatal "who
do we call and by when" hesitation. Concord anchors the evidence to a
git-versioned procedure whose freshness and cosign signature are verified
on every run.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FEDRAMP IR-6: no incident-reporting procedure evidence collected
- FEDRAMP IR-6: no incident-reporting procedure document found at the configured repository path
- FEDRAMP IR-6: incident-reporting procedure <value> is missing required field <value>
- FEDRAMP IR-6: incident-reporting procedure <value> does not name US-CERT/CISA among the authorities to be notified
- FEDRAMP IR-6: incident-reporting procedure <value> was last reviewed <value> days ago (IR-6 expects review at least every <value> days)
- FEDRAMP IR-6: incident-reporting procedure <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-IR-6-incident-reporting
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "IR-6"
  soc2:
  - "CC7.3"
  - "CC2.3"
  iso27001:
  - "A.6.8"
  - "A.5.24"
```

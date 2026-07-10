# System logs the auditable events identified by the organisation

`FEDRAMP-AU-2-event-logging` · framework **fedramp** · severity **high** · Audit and Accountability

## What this control checks

NIST 800-53 AU-2 (Event Logging), as required by the FedRAMP Moderate
baseline, requires the system to log the event categories the organisation
has determined to be auditable, including all successful and unsuccessful
account and privileged actions. Concord verifies that AWS CloudTrail records
management (control-plane) events for both read and write activity and that
at least one data-event selector is configured so that data-plane access to
stored information is captured. Each missing event category is reported
separately, and the check fails closed when no CloudTrail evidence is
present.

## Why it matters

AU-2 defines the set of events the system is expected to log; a trail that
captures write actions but not read actions, or that omits data-plane events
entirely, leaves whole classes of activity invisible to reviewers and
incident responders. CloudTrail models this through event selectors:
management events with a read/write type of "All" cover privileged
control-plane actions in both directions, while data-event selectors capture
object-level access such as S3 GetObject/PutObject. Because a partial event
log cannot satisfy the accountability intent of the control, Concord fails
closed unless every required category is covered.

## Evidence

Collected from the `aws` source (`cloudtrail_event_selectors` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudTrail event-selector evidence collected
- CloudTrail is not logging management (control-plane) read events; privileged read activity is not captured (NIST 800-53 AU-2 / FedRAMP Moderate)
- CloudTrail is not logging management (control-plane) write events; privileged change activity is not captured (NIST 800-53 AU-2 / FedRAMP Moderate)
- CloudTrail has no data-event selector; data-plane access to stored information is not captured (NIST 800-53 AU-2 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AU-2-event-logging
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53: ["AU-2", "AU-2(3)"]
  pci_dss: ["10.2", "10.2.1"]
  soc2: ["CC7.2"]
  cis_aws: ["3.1"]
```

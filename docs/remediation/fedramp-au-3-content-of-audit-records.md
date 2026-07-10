# Audit records contain what type of event, when, where, source, outcome, identity

`FEDRAMP-AU-3-content-of-audit-records` · framework **fedramp** · severity **high** · Audit and Accountability

## What this control checks

NIST 800-53 AU-3 (Content of Audit Records), as required by the FedRAMP
Moderate baseline, requires each audit record to capture what type of event
occurred, when and where it occurred, its source, its outcome, and the
identity of the associated subjects. Concord verifies the CloudTrail
configuration flags that make these fields complete and trustworthy: global
service events must be included so subject identity and origin are recorded
for IAM and STS actions, management events must be recorded so the event
type, source, and name are captured, and log-file validation must be enabled
so records are tamper-evident. The check fails closed when no trail is
present.

## Why it matters

CloudTrail records the fields AU-3 requires in every event, but only when
the trail is configured to capture the relevant activity and to protect the
integrity of what it records. A trail that excludes global service events
silently drops the subject identity and origin for IAM, STS, and other
global actions; a trail without management events omits the event type,
source, and name; and a trail without log-file validation cannot prove its
records were not altered after the fact, which destroys their evidentiary
value during an investigation. Because an incomplete or unverifiable record
cannot satisfy AU-3, Concord fails closed if any of these flags is missing.

## Evidence

Collected from the `aws` source (`audit_trail_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no audit-trail evidence collected
- no CloudTrail trail present; audit-record content cannot be verified — failing closed (NIST 800-53 AU-3 / FedRAMP Moderate)
- CloudTrail trail <value> excludes global service events; subject identity and origin for IAM/STS actions are not recorded (NIST 800-53 AU-3 / FedRAMP Moderate)
- CloudTrail trail <value> does not record management events; event type, source, and name are not captured (NIST 800-53 AU-3 / FedRAMP Moderate)
- CloudTrail trail <value> has log-file validation disabled; audit records are not tamper-evident (NIST 800-53 AU-3 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AU-3-content-of-audit-records
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53: ["AU-3", "AU-3(1)"]
  pci_dss: ["10.3", "10.3.1", "10.3.2"]
  soc2: ["CC7.2", "CC7.3"]
  cis_aws: ["3.2"]
```

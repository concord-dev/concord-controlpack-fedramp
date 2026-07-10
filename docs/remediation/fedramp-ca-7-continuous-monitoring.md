# Continuous monitoring strategy is established and operating

`FEDRAMP-CA-7-continuous-monitoring` · framework **fedramp** · severity **high** · Assessment, Authorization, and Monitoring

## What this control checks

NIST 800-53 Rev 5 CA-7 (FedRAMP Moderate) requires an ongoing monitoring
capability that maintains situational awareness of the security and
privacy posture across the authorization boundary, including monitoring
of system configurations and the detection of threats. Concord verifies
this technically in AWS: the AWS Config recorder must be enabled and
recording in every active region so configuration state is captured
continuously, and Amazon GuardDuty must be enabled in every active region
so threats and anomalous activity are detected continuously. The check
fails closed if no evidence is collected, if no active regions are
reported, if any region's recorder is stopped, or if any region lacks an
enabled detector.

## Why it matters

FedRAMP treats continuous monitoring as the ongoing proof that an
authorization remains valid, not a point-in-time snapshot. A written
ConMon strategy provides no assurance unless the underlying telemetry is
actually flowing: if the AWS Config recorder is stopped in a region,
configuration drift there is invisible; if GuardDuty is disabled,
reconnaissance, credential abuse, and malware activity go undetected.
Anchoring the control to the live state of Config and GuardDuty across
every active region turns "we monitor continuously" into an assertion
that can be falsified on every run, and failing closed prevents an
unmonitored region from silently passing.

## Evidence

Collected from the `aws` source (`config_recorder_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP CA-7: no AWS continuous-monitoring evidence collected — monitoring cannot be verified (fail closed)
- FedRAMP CA-7: no active regions reported — continuous-monitoring coverage cannot be verified (fail closed)
- FedRAMP CA-7: AWS Config recorder is not continuously recording in active region <value> — configuration changes go unmonitored
- FedRAMP CA-7: Amazon GuardDuty is not enabled in active region <value> — threats are not continuously monitored

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-CA-7-continuous-monitoring
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "CA-7"
  - "CA-7(4)"
  soc2:
  - "CC4.1"
  - "CC7.1"
  iso27001:
  - "A.5.36"
```

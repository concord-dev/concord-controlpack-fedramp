# System is monitored to detect attacks and indicators of potential attacks

`FEDRAMP-SI-4-system-monitoring` · framework **fedramp** · severity **high** · System and Information Integrity

## What this control checks

NIST 800-53 Rev 5 SI-4 (System Monitoring), with enhancement SI-4(4)
(Inbound and Outbound Communications Traffic), as required by the FedRAMP
Moderate baseline, requires the organization to monitor the system to detect
attacks and indicators of potential attacks. Concord verifies that AWS
GuardDuty, which analyses VPC flow, DNS, and CloudTrail telemetry for
anomalous and malicious activity, has an enabled detector in every active
region. Each active region without an enabled detector is reported
separately, and the control fails closed when no active region is reported.

## Why it matters

System monitoring only provides assurance if it covers the whole attack
surface; a single region without an enabled GuardDuty detector is a blind
spot where reconnaissance, lateral movement, and data exfiltration proceed
undetected. GuardDuty is a regional service, so coverage must be confirmed
region by region against the set of regions actually in use, and a detector
that exists but is suspended provides no monitoring. Concord fails closed
when no evidence is collected or when no active region is reported, because
absence of monitoring must never be read as compliance.

## Evidence

Collected from the `aws` source (`guardduty_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- SI-4: no system-monitoring evidence collected
- SI-4: no active regions reported; system-monitoring coverage cannot be verified — failing closed (NIST 800-53 SI-4 / FedRAMP Moderate)
- SI-4: GuardDuty system monitoring is not enabled in active region <value> (NIST 800-53 SI-4 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-SI-4-system-monitoring
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "SI-4"
  - "SI-4(4)"
  pci_dss:
  - "11.4"
  soc2:
  - "CC7.2"
```

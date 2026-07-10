# Malicious code protection is employed at entry and exit points

`FEDRAMP-SI-3-malicious-code-protection` · framework **fedramp** · severity **high** · System and Information Integrity

## What this control checks

NIST 800-53 Rev 5 SI-3 (Malicious Code Protection), as required by the
FedRAMP Moderate baseline, requires the organization to employ malicious
code protection mechanisms at system entry and exit points to detect and
eradicate malicious code. Concord verifies that AWS GuardDuty — which
performs continuous threat detection over VPC flow logs, DNS, and
CloudTrail telemetry — has an enabled detector in every active region, and
that Amazon Inspector (vulnerability and malware scanning) is enabled at the
account level. Each active region without an enabled detector is reported
separately.

## Why it matters

Malicious-code detection only provides assurance if it covers the entire
estate; a single region without an enabled GuardDuty detector is a blind
spot where malware command-and-control traffic and credential abuse go
unnoticed, and GuardDuty is a regional service so coverage must be confirmed
region by region. Requiring account-level Inspector in addition ensures
workloads and container images are continuously scanned for known malicious
and vulnerable components. The check fails closed: no evidence, a region
without a detector, or Inspector disabled each fails the control.

## Evidence

Collected from the `aws` source (`anti_malware_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- SI-3: no malicious-code-protection evidence collected
- SI-3: GuardDuty malicious-code detection is not enabled in active region <value> (NIST 800-53 SI-3 / FedRAMP Moderate)
- SI-3: Amazon Inspector is not enabled at the account level; workloads and images are not scanned for malicious code (NIST 800-53 SI-3 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-SI-3-malicious-code-protection
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "SI-3"
  pci_dss:
  - "5.2"
  soc2:
  - "CC6.8"
```

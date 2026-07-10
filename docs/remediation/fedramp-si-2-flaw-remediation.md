# Flaws are identified, reported, and corrected

`FEDRAMP-SI-2-flaw-remediation` · framework **fedramp** · severity **high** · System and Information Integrity

## What this control checks

NIST 800-53 Rev 5 SI-2 (Flaw Remediation), as required by the FedRAMP
Moderate baseline, requires the organization to identify, report, and
correct system flaws and to install security-relevant updates within an
organization-defined time period. FedRAMP defines that period as 30 days
for high-risk vulnerabilities. Concord verifies this technically by reading
AWS Systems Manager (SSM) Patch Manager compliance: every managed instance
in the authorization boundary must report a COMPLIANT patch state, and no
instance may have a missing critical or security patch older than 30 days.

## Why it matters

Unpatched, publicly known vulnerabilities are among the most common root
causes of breaches, because working exploits are widely available soon
after disclosure. Enforcing a 30-day ceiling on missing critical and
security patches, measured directly from SSM Patch Manager rather than a
self-attested spreadsheet, closes the window in which an attacker can
weaponize a known flaw. Evaluating each instance individually means a single
unpatched host fails the control rather than being averaged away by a
healthy fleet, and the fail-closed default treats an instance with no
reported patch state as non-compliant.

## Evidence

Collected from the `aws` source (`ssm_patch_compliance` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- SI-2: no SSM patch-compliance evidence collected
- SI-2: instance <value> reports patch-compliance status <value> (expected COMPLIANT) (NIST 800-53 SI-2 / FedRAMP Moderate)
- SI-2: instance <value> has a missing critical/security patch <value> days old, exceeding the <value>-day FedRAMP SLA (NIST 800-53 SI-2)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **3h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-SI-2-flaw-remediation
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "SI-2"
  - "SI-2(2)"
  - "RA-5"
  pci_dss:
  - "6.2"
  soc2:
  - "CC7.1"
```

# Usage restrictions and configuration for remote access are enforced

`FEDRAMP-AC-17-remote-access` · framework **fedramp** · severity **high** · Access Control

## What this control checks

NIST SP 800-53 Rev 5 AC-17 (Remote Access), as required by the FedRAMP
Moderate baseline, requires the organization to establish and enforce usage
restrictions and configuration requirements for each type of remote access,
including routing through managed access-control points and protecting
confidentiality and integrity with cryptography (AC-17(2)). Concord inspects
every security group and fails any ingress rule that exposes a
remote-administration port (SSH 22, RDP 3389) directly to the Internet
(0.0.0.0/0 or ::/0), and any rule marked as remote administrative access
that is not confirmed to be encrypted.

## Why it matters

An SSH or RDP port open to 0.0.0.0/0 is one of the highest-signal findings
an assessor can identify: it hands every host on the Internet a login prompt
to the authorization boundary and bypasses the managed access points AC-17
requires. Equally, an administrative path that cannot demonstrate encryption
exposes privileged credentials to interception. By requiring that remote
administration is both restricted to trusted sources and cryptographically
protected, the control enforces the intent of AC-17 rather than checking a
single port. It fails closed: a rule that does not affirm encryption is
denied rather than presumed safe.

## Evidence

Collected from the `aws` source (`security_groups` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security-group evidence collected — cannot verify remote-access restrictions (NIST 800-53 AC-17 / FedRAMP Moderate)
- security group <value> exposes remote administration via <value> (port <value>) to the untrusted network <value> — remote access must be restricted to authorized, managed sources (NIST 800-53 AC-17 / FedRAMP Moderate)
- security group <value> permits remote administrative access on ports <value>-<value> that is not confirmed to use encryption — remote access must use cryptographic protection (NIST 800-53 AC-17(2) / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AC-17-remote-access
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "AC-17"
  - "AC-17(2)"
  soc2:
  - "CC6.6"
  - "CC6.7"
  pci_dss:
  - "1.3.1"
  - "2.3"
```

# System monitors and controls communications at external boundaries

`FEDRAMP-SC-7-boundary-protection` · framework **fedramp** · severity **critical** · System and Communications Protection

## What this control checks

NIST 800-53 Rev 5 SC-7 (Boundary Protection), as required by the FedRAMP
Moderate baseline, directs the system to monitor and control communications
at the external boundary of the authorization boundary and at key internal
boundaries, denying network traffic by default and allowing it by exception.
Concord verifies this technically by inspecting every AWS security group:
any group classified as protecting an internal tier (private or restricted)
must not permit direct ingress from an untrusted network (0.0.0.0/0 or
::/0). Every group must also declare the tier it protects so isolation of
internal resources can be confirmed rather than assumed.

## Why it matters

Direct Internet reachability of an internal database, application backend,
or management interface is one of the highest-signal findings a FedRAMP
assessor (3PAO) can identify: it means the boundary that is supposed to sit
between untrusted networks and federal information is missing or
misconfigured. By classifying each security group by the tier it protects
and requiring that private and restricted tiers have zero direct ingress
from the Internet, this control enforces the "deny-all, permit-by-exception"
intent of SC-7 rather than merely checking a handful of well-known ports.
The check fails closed: a security group that does not declare its tier
cannot be shown to sit on the trusted side of the boundary and is denied.

## Evidence

Collected from the `aws` source (`security_groups` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- SC-7: no security-group evidence collected
- SC-7: security group <value> protects a <value>-tier resource but permits direct inbound from the untrusted network <value>; the authorization boundary must deny all direct Internet access to internal resources (NIST 800-53 SC-7 / FedRAMP Moderate)
- SC-7: security group <value> does not declare the network tier it protects; every group must be classified so internal tiers can be confirmed isolated from untrusted networks (NIST 800-53 SC-7 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-SC-7-boundary-protection
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "SC-7"
  - "SC-7(3)"
  - "SC-7(4)"
  pci_dss:
  - "1.3.1"
  soc2:
  - "CC6.6"
```

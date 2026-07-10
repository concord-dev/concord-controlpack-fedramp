# The system provides only essential capabilities

`FEDRAMP-CM-7-least-functionality` · framework **fedramp** · severity **medium** · Configuration Management

## What this control checks

NIST 800-53 Rev 5 CM-7 (Least Functionality) and CM-7(1), required by the
FedRAMP Moderate baseline, require the system to be configured to provide
only essential capabilities and to prohibit or restrict the use of
unnecessary or insecure functions, ports, protocols, and services. Concord
inspects every AWS security group and denies any ingress rule that permits a
known unnecessary or insecure legacy service — such as FTP, Telnet, TFTP,
the NetBIOS/SMB family, RPC/portmapper, NFS, rsync, VNC, or X11 — and any
rule that opens all ports and protocols, which necessarily exposes those
services. An absent evidence payload denies.

## Why it matters

Every enabled service is attack surface, and legacy services such as Telnet,
FTP, and SMB carry credentials or data in the clear and are repeatedly
implicated in breaches. Assessors validating CM-7 expect the configuration
to disable functionality that is not needed; the fastest evidence it has not
been applied is a firewall rule that still permits one of these services.
Enumerating the unnecessary-service ports and failing closed on any
"all ports" rule turns that expectation into a concrete, repeatable check.
The control fails closed — absent security-group evidence denies rather than
assuming the environment is hardened.

## Evidence

Collected from the `aws` source (`security_groups` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security-group evidence collected — cannot demonstrate least functionality (NIST 800-53 CM-7 / FedRAMP Moderate)
- security group <value> permits <value> (port <value>) from <value> — this unnecessary/insecure service must be disabled (NIST 800-53 CM-7 / FedRAMP Moderate)
- security group <value> permits all ports and protocols inbound from <value>, necessarily exposing unnecessary and insecure services (NIST 800-53 CM-7 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-CM-7-least-functionality
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "CM-7"
  - "CM-7(1)"
  pci_dss:
  - "2.2.5"
  cis_aws:
  - "5.2"
```

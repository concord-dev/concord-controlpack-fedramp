# Configuration settings are established and enforced for system components

`FEDRAMP-CM-6-configuration-settings` · framework **fedramp** · severity **medium** · Configuration Management

## What this control checks

NIST 800-53 Rev 5 CM-6 (Configuration Settings), required by the FedRAMP
Moderate baseline, requires the organization to establish, document, and
enforce mandatory configuration settings for system components using
security configuration checklists. In AWS this is proven by benchmark-
aligned AWS Config conformance packs that continuously evaluate live
resources. Concord reads the conformance-pack status and denies when no pack
is deployed, when no benchmark-aligned pack (FedRAMP or CIS) is present, or
when any deployed pack reports a state other than COMPLIANT. An absent
evidence payload denies.

## Why it matters

A documented hardening standard is worthless unless deviations from it are
detected automatically against running resources. Mapping a FedRAMP- or
CIS-aligned conformance pack onto AWS Config turns the checklist into
continuous, evidence-backed detection: a NON_COMPLIANT pack means live
resources have diverged from the mandatory settings and must be remediated,
and the absence of any benchmark pack means the settings are not enforced at
all. The control fails closed — missing evidence, a missing benchmark pack,
or a non-COMPLIANT pack denies rather than assuming settings are enforced.

## Evidence

Collected from the `aws` source (`config_conformance_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no AWS Config conformance evidence collected — cannot demonstrate enforced configuration settings (NIST 800-53 CM-6 / FedRAMP Moderate)
- no Config conformance pack is deployed to enforce configuration settings (NIST 800-53 CM-6 / FedRAMP Moderate)
- no benchmark-aligned Config conformance pack (FedRAMP or CIS) is deployed to enforce configuration settings (NIST 800-53 CM-6 / FedRAMP Moderate)
- Config conformance pack <value> is <value> (expected COMPLIANT) (NIST 800-53 CM-6 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **4h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-CM-6-configuration-settings
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "CM-6"
  - "CM-2"
  pci_dss:
  - "2.2.1"
  cis_aws:
  - "3.5"
```

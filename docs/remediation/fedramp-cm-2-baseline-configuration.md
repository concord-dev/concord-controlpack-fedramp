# A current baseline configuration of the system is maintained

`FEDRAMP-CM-2-baseline-configuration` · framework **fedramp** · severity **high** · Configuration Management

## What this control checks

NIST 800-53 Rev 5 CM-2 (Baseline Configuration), required by the FedRAMP
Moderate baseline, requires the organization to develop, document, and
maintain a current baseline configuration of the system. In AWS this is
proven by the AWS Config recorder being enabled and recording in every
active region, so the configuration of all resources is continuously and
authoritatively captured. Concord reads the Config recorder status and
denies any active region where the recorder is absent or not recording, and
denies when no active regions are reported at all. An absent evidence
payload denies.

## Why it matters

A baseline configuration provides no assurance unless the current
configuration of every resource is continuously captured and comparable to
it. The AWS Config recorder produces exactly that authoritative,
tamper-evident record; if it is disabled in a region, configuration drift
there is invisible and no baseline can be maintained for those resources.
Requiring recording in every active region prevents the false assurance of a
baseline that only covers part of the estate. The control fails closed —
missing evidence or a non-recording region denies rather than assuming
coverage.

## Evidence

Collected from the `aws` source (`config_recorder_status` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no AWS Config recorder evidence collected — cannot demonstrate a maintained baseline configuration (NIST 800-53 CM-2 / FedRAMP Moderate)
- no active regions reported — cannot demonstrate baseline configuration recording (NIST 800-53 CM-2 / FedRAMP Moderate)
- AWS Config recorder is not recording in active region <value> — baseline configuration is not captured there (NIST 800-53 CM-2 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-CM-2-baseline-configuration
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "CM-2"
  - "CM-8"
  pci_dss:
  - "2.2.1"
  cis_aws:
  - "3.5"
```

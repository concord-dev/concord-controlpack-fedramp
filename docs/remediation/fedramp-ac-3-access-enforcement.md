# System enforces approved authorisations for logical access

`FEDRAMP-AC-3-access-enforcement` · framework **fedramp** · severity **critical** · Access Control

## What this control checks

NIST SP 800-53 Rev 5 AC-3 (Access Enforcement), as required by the FedRAMP
Moderate baseline, requires the system to enforce approved authorizations
for logical access to information and system resources in accordance with
applicable access-control policy. In AWS this rests on IAM's deny-by-default
model. Concord inspects the effect statements of every attached IAM policy
and fails any statement that subverts that model: an Allow of Action "*" on
Resource "*" (an explicit allow-all), or an Allow that uses NotAction or
NotResource, which inverts the policy into "allow everything except" and
re-opens the default-deny baseline as new actions or resources appear.

## Why it matters

AWS IAM enforces approved authorizations only until a single over-broad
Allow statement negates the default-deny stance. The two most dangerous
patterns are an outright Allow of "*"/"*" and the subtle Allow +
NotAction/NotResource idiom, which grants every action or resource except a
short deny-list and therefore fails open whenever a new service appears.
FedRAMP assessors reviewing AC-3 look precisely for statements that break
the default-deny posture. The control fails closed: with no policy evidence
it denies rather than presuming access enforcement is intact.

## Evidence

Collected from the `aws` source (`iam_policies` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM policy evidence collected — cannot verify access enforcement defaults to deny-all (NIST 800-53 AC-3 / FedRAMP Moderate)
- IAM <value> <value> policy <value> allows Action "*" on Resource "*" — an explicit allow-all defeats enforcement of approved authorizations (NIST 800-53 AC-3 / FedRAMP Moderate)
- IAM <value> <value> policy <value> uses Allow + NotAction — this allows every action except a deny-list and subverts deny-by-default access enforcement (NIST 800-53 AC-3 / FedRAMP Moderate)
- IAM <value> <value> policy <value> uses Allow + NotResource — this allows access to every resource except a deny-list and subverts deny-by-default access enforcement (NIST 800-53 AC-3 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AC-3-access-enforcement
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "AC-3"
  soc2:
  - "CC6.1"
  - "CC6.3"
  pci_dss:
  - "7.3"
  - "7.3.3"
```

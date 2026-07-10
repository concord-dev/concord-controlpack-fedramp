# Principle of least privilege is enforced for all authorized accesses

`FEDRAMP-AC-6-least-privilege` · framework **fedramp** · severity **high** · Access Control

## What this control checks

NIST SP 800-53 Rev 5 AC-6 (Least Privilege), as required by the FedRAMP
Moderate baseline, requires the organization to employ the principle of
least privilege, allowing only the authorizations necessary for users (and
processes acting on their behalf) to accomplish assigned tasks. Concord
reads every IAM identity (user, group, and role) together with its attached
managed and inline policies and fails any identity that carries the
AWS-managed AdministratorAccess policy or a statement allowing Action "*"
on Resource "*". A standing full-admin grant is broader than any single job
function requires and therefore cannot satisfy least privilege.

## Why it matters

Broad "*/*" grants are the most common way least privilege erodes: a role
created for one task accumulates AdministratorAccess and quietly becomes a
path to every resource in the account. FedRAMP assessors treat an
unconstrained admin grant attached to a routine identity as an immediate
AC-6 finding because it defeats the ability to tie each permission back to a
documented, least-privilege authorization. The check fails closed: when no
IAM policy evidence is collected it denies rather than assuming least
privilege holds.

## Evidence

Collected from the `aws` source (`iam_policies` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM policy evidence collected — cannot demonstrate least privilege (NIST 800-53 AC-6 / FedRAMP Moderate)
- IAM <value> <value> is attached to AdministratorAccess — standing full-admin access is broader than least privilege permits (NIST 800-53 AC-6 / FedRAMP Moderate)
- IAM <value> <value> attaches policy <value> allowing Action "*" on Resource "*" — the grant exceeds the privileges any job function requires (NIST 800-53 AC-6 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AC-6-least-privilege
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "AC-6"
  soc2:
  - "CC6.1"
  - "CC6.3"
  pci_dss:
  - "7.1"
  - "7.2.1"
```

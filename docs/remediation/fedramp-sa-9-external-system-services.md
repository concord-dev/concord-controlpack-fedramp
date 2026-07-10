# External system services are governed and monitored

`FEDRAMP-SA-9-external-system-services` · framework **fedramp** · severity **medium** · System and Services Acquisition

## What this control checks

NIST 800-53 Rev 5 SA-9 (FedRAMP Moderate) requires providers of external
system services to comply with organization-defined security and privacy
requirements, and requires the organization to define and monitor those
services and their controls on an ongoing basis. Concord reads the
version-controlled external-services governance record from the
repository and confirms it maintains a service inventory, states the
security requirements imposed on providers, describes the ongoing
monitoring process, that it was reviewed within the last year, and that
it carries a verified signature.

## Why it matters

Data and functionality that leave the authorization boundary do not leave
the organization's responsibility. SA-9 is the control that keeps SaaS,
subservice organizations, and other third parties from becoming
unmanaged extensions of the system. A governance record with no inventory
cannot claim to know its dependencies; one with no monitoring process
cannot claim the providers still meet their obligations. Anchoring the
check to a git-versioned, signed record lets Concord verify on every run
that the inventory, requirements, and monitoring are documented and
current, closing the third-party blind spot rather than assuming it.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP SA-9: no external-system-services evidence collected
- FedRAMP SA-9: no external-services governance document found at the configured repository path
- FedRAMP SA-9: external-services record <value> is missing required field <value>
- FedRAMP SA-9: external-services record <value> was last reviewed more than <value> days ago (last_reviewed_at=<value>)
- FedRAMP SA-9: external-services record <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-SA-9-external-system-services
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "SA-9"
  - "SA-9(2)"
  soc2:
  - "CC9.2"
  iso27001:
  - "A.5.19"
  - "A.5.22"
```

# Access is terminated upon personnel termination

`FEDRAMP-PS-4-personnel-termination` · framework **fedramp** · severity **high** · Personnel Security

## What this control checks

NIST SP 800-53 Rev 5 control PS-4 (Personnel Termination), required at the
FedRAMP Moderate baseline, requires the organisation to disable system access
within an organisation-defined time period when individual employment ends.
Unlike the surrounding personnel-security controls, this outcome is directly
observable from the identity provider, so Concord queries the IdP for every
user marked SUSPENDED, DEPROVISIONED, or DELETED within the lookback window
and verifies each terminated user has no active session, no active
application assignments, and no admin role memberships, and that access was
revoked within 24 hours of termination.

## Why it matters

Lingering identity-provider access for terminated staff is one of the most
common and most damaging control failures: a departed employee's still-active
SSO session or admin role is a credential outside the organisation's control.
A written offboarding procedure proves intent but not execution — the IdP
proves execution. By reading terminated-user state straight from the identity
provider rather than accepting an attestation, Concord catches the account
that slipped through the offboarding checklist, and enforces the 24-hour
revocation window FedRAMP assessors expect for prompt deactivation.

## Evidence

Collected from the `okta` source (`terminated_users` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FedRAMP PS-4: no identity-provider termination evidence collected
- FedRAMP PS-4: terminated user <value> still has an active session
- FedRAMP PS-4: terminated user <value> still has <value> active application assignment(s)
- FedRAMP PS-4: terminated user <value> still has admin role(s): <value>
- FedRAMP PS-4: terminated user <value> access was revoked <value> hours after termination (FedRAMP Moderate floor is <value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **30m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-PS-4-personnel-termination
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "PS-4"
  - "AC-2(3)"
  hipaa:
  - "164.308(a)(3)(ii)(C)"
  iso27001:
  - "A.6.5"
  soc2:
  - "CC6.3"
```

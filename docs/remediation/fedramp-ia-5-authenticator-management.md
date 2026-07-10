# Authenticator management is governed by complexity, lifetime, and reuse policy

`FEDRAMP-IA-5-authenticator-management` · framework **fedramp** · severity **high** · Identification and Authentication

## What this control checks

NIST 800-53 Rev 5 IA-5 (Authenticator Management) and IA-5(1)
(Password-based Authentication), required by the FedRAMP Moderate baseline,
require the organization to manage authenticators by establishing minimum
strength, complexity, rotation cadence, and reuse-prevention. Concord reads
the AWS IAM account password policy and denies it when the policy is weaker
than the FedRAMP Moderate minimums: minimum length below 12, any missing
character class (uppercase, lowercase, number, symbol), a maximum password
age above 60 days (or no expiry), or reuse-prevention remembering fewer
than 24 previous passwords. An absent or unconfigured policy denies.

## Why it matters

The password policy is the single account-wide lever that governs every
console credential, so a weak or missing policy silently undermines every
downstream authentication control. IA-5(1) fixes concrete parameters —
length, complexity, rotation, and reuse — precisely because ad-hoc password
hygiene does not survive contact with real users. Checking the live IAM
account policy against the FedRAMP minimums turns the written requirement
into automated, evidence-backed enforcement. The control fails closed: if no
policy is configured or no evidence is collected it denies rather than
assuming a compliant policy exists.

## Evidence

Collected from the `aws` source (`iam_password_policy` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no IAM password policy evidence collected (NIST 800-53 IA-5 / FedRAMP Moderate)
- no IAM account password policy is configured — IA-5(1) requires one (FedRAMP Moderate)
- minimum_password_length is <value>, must be >= <value> (NIST 800-53 IA-5(1) / FedRAMP Moderate)
- require_symbols is false — IA-5(1) requires symbol complexity (FedRAMP Moderate)
- require_numbers is false — IA-5(1) requires digit complexity (FedRAMP Moderate)
- require_uppercase_characters is false — IA-5(1) requires uppercase complexity (FedRAMP Moderate)
- require_lowercase_characters is false — IA-5(1) requires lowercase complexity (FedRAMP Moderate)
- expire_passwords is false; max_password_age must be set to <= <value> days (NIST 800-53 IA-5(1) / FedRAMP Moderate)
- max_password_age is <value>, must be <= <value> days (NIST 800-53 IA-5(1) / FedRAMP Moderate)
- password_reuse_prevention is <value>, must remember >= <value> previous passwords (NIST 800-53 IA-5(1) / FedRAMP Moderate)
- users cannot change their own passwords — required for rotation hygiene (NIST 800-53 IA-5)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2h**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-IA-5-authenticator-management
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "IA-5"
  - "IA-5(1)"
  cis_aws:
  - "1.16"
  pci_dss:
  - "8.3.6"
```

# System recovery and reconstitution procedures are current, signed, and tested

`FEDRAMP-CP-10-system-recovery-and-reconstitution` · framework **fedramp** · severity **high** · Contingency Planning

## What this control checks

NIST SP 800-53 Rev 5 CP-10 (System Recovery and Reconstitution) requires
the organization to provide for the recovery and reconstitution of the
system to a known state after a disruption, compromise, or failure. FedRAMP
Moderate expects documented, tested procedures that restore the system to
an operational state (recovery) and return it to a fully secure, verified
configuration (reconstitution). Concord reads the version-controlled
recovery-and-reconstitution procedures from the repository and confirms
they declare the recovery procedures, the reconstitution steps, a recent
test, and a recent signed review.

## Why it matters

Recovery restores service; reconstitution proves the restored system is
trustworthy — patched to the current baseline, free of attacker footholds,
and validated against the approved configuration. Teams that document
recovery but skip reconstitution routinely bring a system back only to
reintroduce the very weakness that caused the outage. CP-10 requires both,
and requires them to be tested. Concord anchors the evidence to a
git-versioned document whose review freshness, test freshness, and cosign
signature are verified on every run, so an assessor sees the procedures are
complete, exercised, and approved.

## Evidence

Collected from the `github` source (`file_glob` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- FEDRAMP CP-10: no system-recovery-and-reconstitution evidence collected
- FEDRAMP CP-10: no system-recovery-and-reconstitution document found at the configured repository path
- FEDRAMP CP-10: recovery/reconstitution procedures <value> are missing required field <value>
- FEDRAMP CP-10: recovery/reconstitution procedures <value> were last reviewed <value> days ago (CP-10 expects review at least every <value> days)
- FEDRAMP CP-10: recovery/reconstitution procedures <value> were last tested <value> days ago (CP-10 expects testing at least every <value> days)
- FEDRAMP CP-10: recovery/reconstitution procedures <value> signature is not verified (signature_verified=<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-CP-10-system-recovery-and-reconstitution
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "CP-10"
  soc2:
  - "A1.3"
  - "CC7.5"
  iso27001:
  - "A.5.29"
  - "A.5.30"
```

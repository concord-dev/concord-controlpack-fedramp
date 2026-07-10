# Audit records are reviewed and analysed for indications of inappropriate activity

`FEDRAMP-AU-6-audit-review-analysis-reporting` · framework **fedramp** · severity **high** · Audit and Accountability

## What this control checks

NIST 800-53 AU-6 (Audit Record Review, Analysis, and Reporting), as required
by the FedRAMP Moderate baseline, requires audit records to be reviewed and
analysed for indications of inappropriate or unusual activity, with findings
reported to designated personnel. Concord verifies the automated review
mechanism: AWS CloudWatch metric alarms must exist for the required
security-event categories (unauthorised API calls, root-account usage, IAM
policy changes, and failed console sign-ins) and each alarm must have an
active notification action so detected events are reported to responders.
Each uncovered category is reported separately.

## Why it matters

Manual review of raw audit records does not scale, so AU-6(1) expects
automated mechanisms to integrate review, analysis, and reporting.
CloudWatch metric filters paired with alarms are the canonical AWS
implementation and align with the CIS AWS Foundations monitoring benchmarks.
An alarm that exists but has no notification action is equivalent to no
review at all, because a triggered condition never reaches a human, so
Concord requires both a configured alarm and a wired-up SNS action for every
required category. Missing coverage of any category means a whole class of
suspicious activity would go unreviewed and unreported, so the control fails
closed.

## Evidence

Collected from the `aws` source (`cloudwatch_metric_alarms` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no CloudWatch metric-alarm evidence collected
- no CloudWatch metric alarm with an active notification reviews security-event category <value> (NIST 800-53 AU-6 / FedRAMP Moderate)
- CloudWatch metric alarm <value> has no notification action; <value> events would not be reported for review (NIST 800-53 AU-6 / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **45m**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-AU-6-audit-review-analysis-reporting
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53: ["AU-6", "AU-6(1)", "AU-6(3)"]
  pci_dss: ["10.6", "10.6.1"]
  soc2: ["CC7.2", "CC7.3"]
  cis_aws: ["4.1", "4.3", "4.4"]
```

# Confidentiality and integrity of transmitted information are protected

`FEDRAMP-SC-8-transmission-confidentiality-and-integrity` · framework **fedramp** · severity **critical** · System and Communications Protection

## What this control checks

NIST 800-53 Rev 5 SC-8 (Transmission Confidentiality and Integrity), with
enhancement SC-8(1) (Cryptographic Protection), as required by the FedRAMP
Moderate baseline, requires the system to protect the confidentiality and
integrity of transmitted information using approved cryptography. Concord
inspects the two endpoints that carry information across the authorization
boundary in a typical AWS estate: S3 buckets and Elastic Load Balancer
listeners. Every bucket must carry a policy that denies requests where
aws:SecureTransport is false, and every listener must speak HTTPS/TLS with a
security policy whose minimum negotiated protocol is TLS 1.2. Plaintext
listeners, weak TLS policies, and buckets without the SecureTransport deny
all fail.

## Why it matters

AWS permits TLS but does not force it — an S3 bucket without a
SecureTransport deny will serve federal information over plaintext HTTP, and
an ELB listener pinned to an ELBSecurityPolicy that still allows TLS 1.0/1.1
is exposed to well-known downgrade and BEAST-class attacks. FedRAMP requires
FIPS-validated cryptography for data in transit, so the enforcement
mechanism (a bucket-policy deny and a TLS-1.2-minimum listener policy) must
be present, not merely available. The check fails closed: missing evidence
or an unrecognised TLS policy denies rather than passes.

## Evidence

Collected from the `aws` source (`aws_tls_endpoints` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- SC-8: no transmission-endpoint evidence collected
- SC-8: S3 bucket <value> does not deny non-TLS requests (missing aws:SecureTransport=false deny); transmitted information must be TLS-protected (NIST 800-53 SC-8 / FedRAMP Moderate)
- SC-8: load balancer <value> has a <value> listener on port <value> that transmits information without TLS (NIST 800-53 SC-8 / FedRAMP Moderate)
- SC-8: load balancer <value> listener on port <value> uses SSL policy <value> which permits TLS below 1.2 (NIST 800-53 SC-8(1) / FedRAMP Moderate)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **1d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework fedramp --control-id FEDRAMP-SC-8-transmission-confidentiality-and-integrity
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  nist_800_53:
  - "SC-8"
  - "SC-8(1)"
  hipaa:
  - "164.312(e)(2)(ii)"
  soc2:
  - "CC6.7"
```

# concord-controlpack-fedramp

FedRAMP Moderate Baseline control pack for Concord — 50 controls across
the 17 NIST 800-53 Rev 5 control families that make up the FedRAMP
Moderate baseline.

## Install

```sh
concord add fedramp
```

(Resolves via `concord-framework-fedramp` which pins this pack.)

## Coverage

v0.1.0 ships 50 controls — the core baseline for AC, AU, CA, CM, CP,
IA, IR, MA, MP, PE, PL, PS, RA, SA, SC, SI families. Subsequent
releases add the remaining baseline controls and FedRAMP overlays as
the underlying OPA rules mature.

Every control validates with `concord control validate` (pass + fail
fixtures match the rego).

## Source

Drawn from
[usnistgov/oscal-content](https://github.com/usnistgov/oscal-content)
FedRAMP profiles. Control IDs follow the FedRAMP-`<NIST-ID>`-`<slug>`
convention so OSCAL component-definition export round-trips cleanly.

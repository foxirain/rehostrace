# Claim model

RehostRace separates four common claims:

- **mechanism** — the trace, scheduler, model, or oracle behaves as specified;
- **path** — a particular component executed a particular path under named inputs;
- **consequence** — an environment exhibited an externally observable effect;
- **impact** — the effect is exploitable or crosses a security boundary.

A public synthetic fixture can strongly support a mechanism claim. It does not, by itself, support path, consequence, or impact claims for another binary or device.

Every evidence receipt contains:

- `allowed_claims`: claims supported by the evidence class;
- `forbidden_claims`: tempting but unsupported transfers;
- `asserted_claims`: the subset actually made by the experiment; and
- a prose `claim_boundary` for readers.

Missing evidence must produce `inconclusive`, `not-run`, or `not-applicable`; it must not be converted to a pass. If instrumentation changes timing or scheduling, record that observer effect as a fidelity limitation or a separately measured calibration.

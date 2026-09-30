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

`finding.same-object-lifetime` states that the named sinks shared an object
identity under the bound execution. `mechanism.allocation-provenance` additionally
states that the declared input, producer, allocation site, size class, and object
generation were observed. `finding.foreign-owner-free` additionally states that
a stale actor freed the replacement owner's generation. None of these claims
alone establish stock reachability, harmful consequence, exploitability, or code
execution.

An `oracle-campaign` result adds repeatability and uncertainty evidence for the
same declared experiment. A stable positive proportion is not a device trigger
probability unless the campaign policy and a separate transfer argument bind
the tested scheduler, inputs, artifacts, and environment to that device claim.

# Allocation provenance and foreign-owner free

A same-address lifetime result is not enough to show who created the replacement
object or why it appeared. A test controller can make a race look stronger by
allocating the replacement itself. RehostRace therefore treats allocation
provenance as a separate, fail-closed evidence contract.

## Required causal chain

The `rehostrace.reclaim-oracle/v1` contract requires this exact sequence:

```text
original free
  -> boundary input
  -> replacement allocation by the declared target producer
  -> stale-path read from the replacement generation
  -> write carrying the observed value
  -> stale-path free of the replacement owner
  -> optional post-free alias allocation
```

The oracle checks four independent properties:

1. **Identity** — every lifetime sink uses the same opaque address token, while
   the original and replacement generations differ.
2. **Provenance** — a named boundary event and operation caused the allocation
   at the declared target callsite and size class; forbidden producers did not.
3. **Ownership** — the replacement belongs to a new logical owner, but the stale
   actor reads and frees it.
4. **Effect** — the value read at the declared offset is the value later written
   to the declared target.

Missing or malformed observations produce `inconclusive`. A complete trace that
contradicts the contract produces `negative`. Only a complete trace satisfying
every check produces `positive`.

## Address privacy

The `object` field is an adapter-issued opaque token, not a raw address. An
integration can hash or remap runtime addresses as long as equality is stable
within the receipt. The `generation` field distinguishes separate allocations
that occupied the same address token.

## Public demo

Run:

```bash
make reclaim-demo
```

The synthetic fixture emits:

- `out/reclaim_provenance/oracle-result.json`
- `out/reclaim_provenance/evidence-receipt.json`

The receipt may assert `mechanism.allocation-provenance` and
`finding.foreign-owner-free` for its bound observations. It explicitly forbids
transfer to product reachability, harmful stock consequences, exploitability,
or code execution.

Target integrations should keep private offsets, binaries, traces, and schedules
outside the public framework. They can use the same schema and SDK while binding
their own evidence under an appropriate disclosure class.

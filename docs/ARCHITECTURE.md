# Architecture

RehostRace treats a rehosting result as a chain of independently checkable contracts.

```text
passive records -> causal trace -> protocol pack -> replay -> oracle -> receipt
                         |                                  ^
binary CFG -> candidate -> target lowering -> controller --+
                         |                    ^
                         +-> detailed schedule+
version manifests -> semantic differential
```

## Causal trace

Events form a directed acyclic graph. Actor program order and explicit synchronization create happens-before edges; events without a path remain concurrent. Timestamps are metadata and cannot silently impose order across clock domains.

## Binding and schedule

A binding maps selected boundary events to adapter actions and is hash-bound to both the trace and schedule. A schedule names semantic points, signals, waits, counters, and selectors. This keeps race control separate from transport encoding and allows a schedule to fail closed when identities drift.

## Replay and oracle

Replay accepts only a valid linear extension of the causal graph. Adapters implement boundary semantics and maintain state. Oracles consume observations and distinguish positive, negative, and inconclusive results. A lifetime claim requires identity equality at the relevant sinks, not merely two similar log lines.

## Evidence receipt

A receipt hashes inputs, records the executor and event order, embeds oracle results, labels fidelity dimensions, and lists which claims may or may not transfer. Receipts are evidence envelopes, not automatic proof that two environments are equivalent.

## Extension point

A target integration belongs outside the framework core until it can be represented through public interfaces. It should provide a capture adapter, action adapter, observation extractor, oracle, and fidelity policy. Proprietary inputs and unpublished schedules stay in a separate, access-controlled workspace.

## Bluetooth layers

The Bluetooth subsystem deliberately separates five interfaces:

1. a data-only protocol-pack manifest;
2. an explicitly trusted handler registry;
3. a semantic lifecycle model;
4. an optional byte-parser harness used by the offline fuzzer; and
5. a target adapter that projects accepted events into a concrete runtime.

The public profile handlers validate lifecycle state. They do not parse every
wire field and do not emulate a controller or radio. Native host-stack and
controller execution plans are separately hash-pinned so that adding either
backend does not silently promote the fidelity of portable-model evidence.

## Automated analysis boundary

The normalized CFG analyzer finds asynchronous paths that share lifetime
sinks and produces candidate schedules with an explicit same-identity oracle.
This is automated after CFG normalization. The existing relocatable-object
reader supplies one extraction path; arbitrary stripped-binary recovery is an
open extractor problem and is not implied by the candidate analysis.

The lowering compiler begins after candidate discovery. It checks that the
analysis, candidate set, detailed schedule, declared target binary identity,
role classifiers, hook selectors, expected instruction hashes, object
captures, and symbol relations are internally consistent. It then emits a content-addressed controller plan and a
data-only C header. Target-specific symbol and register recovery remains an
explicit fact-producing step; the compiler does not pretend to infer facts it
was not given. The integration layer must compare the declared binary and
instruction hashes with the actual artifact. See
[TARGET_LOWERING.md](TARGET_LOWERING.md).

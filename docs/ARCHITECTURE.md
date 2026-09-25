# Architecture

RehostRace treats a rehosting result as a chain of independently checkable contracts.

```text
boundary capture -> causal trace -> binding -> schedule -> replay -> oracle -> receipt
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

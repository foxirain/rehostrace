# Full Bluetooth research roadmap

This document distinguishes implemented mechanisms from integration contracts
and research still needed. “Implemented” means a checked-in public fixture is
executed by `make verify`; it does not mean complete protocol conformance or a
finding on a physical target.

## Current capability matrix

| Area | Current status | Public evidence | Remaining boundary |
| --- | --- | --- | --- |
| HCI, ACL, L2CAP, AVDTP, SDP, ATT, GATT | Executed semantic models | Three original causal slices | Broader wire grammar and conformance |
| SMP | Executed semantic lifecycle and bounded PDU parser | Pairing slice plus representative PDU tests | Key distribution state and all association models |
| RFCOMM and HFP | Executed lifecycle and bounded frame/AT parsers | Credit/data, AT request/response, audio lifecycle | Full multiplexer, FCS verification, HSP and synchronous transport |
| AVRCP and A2DP | Executed lifecycle and bounded AVCTP/RTP parsers | Command/response and media lifecycle | Complete AV/C operands, codecs and fragmentation |
| LE Audio | Executed lifecycle and bounded HCI ISO parser | Group, CIS and ISO-data lifecycle | Full ASCS/PACS/BAP wire models and controller ISO timing |
| Coverage-guided fuzzing | Executed deterministic engine | Seeded public parser campaign | Instrumented native parsers and distributed workers |
| Passive capture to replay | Executed compiler and replay | Public capture bundle to HCI replay | Target collectors and protocol-specific normalization |
| CFG lifetime analysis | Executed normalized analysis | Public lock-handoff multi-free candidate | More binary front ends, alias analysis and interprocedural recovery |
| Schedule synthesis | Executed structural candidate synthesis | Same-resource identity oracle requirement | Runtime feedback, minimal-gate search and probabilistic ranking |
| Candidate-to-target lowering | Executed plan/header generation; generic kprobe consumer present | Synthetic hash-bound roles, points, captures and relations | Automated target-fact extraction and public runtime integration |
| Version differential | Executed hash/ABI/fact comparison | Two public target manifests | Automated extraction for every supported artifact kind |
| Native host stack | Validated execution contract only | Hash-pinned plan | A backend that builds, boots, instruments and attests the stack |
| Controller firmware | Validated execution contract only | Hash-pinned plan | Architecture-specific loader, peripherals, interrupts and coverage |

## Seven requested expansion tracks

### 1. Protocol packs

The registry now covers SMP, RFCOMM, AVRCP, HFP, A2DP and LE Audio in addition
to the original packs. Each handler owns a fail-closed state machine, and each
manifest remains data-only. A manifest cannot cause Python code to be imported;
applications must register a trusted factory explicitly.

Bounded byte-level parsers now cover one representative framing layer for each
new protocol family. They reject unsupported forms. The next layer is complete
wire coverage and adapters that translate decoded packets into the same
semantic operations, so a trace can be replayed whether it came from a
synthetic test, a native parser, or a redacted live capture.

### 2. Coverage-guided parser fuzzing

`CoverageGuidedFuzzer` uses deterministic mutations, stable semantic feature
tokens, content hashes, bounded inputs, and explicit `ok`, `reject`, `crash`,
or `hang` outcomes. The public campaign proves queue behavior and finding
retention against an intentionally seeded parser. It does not claim coverage
of a production parser.

### 3. Native host-stack rehosting

The public plan fixes target and runner hashes, transport, reset policy, stage
order, timeouts, inputs, and evidence outputs. A real backend must additionally
attest the build inputs, runtime image, sanitizer configuration, coverage
mapping, and causal boundary trace. Until that backend is present, the plan's
`executable` field remains false.

### 4. Controller-firmware harness

Controller work is isolated from host-stack evidence because firmware loaders,
peripherals, DMA, interrupts, coexistence, and radio timing have different
fidelity requirements. The current artifact is an execution contract, not a
controller emulator. A future backend should map HCI command/event streams and
interrupt schedules into an architecture-specific runner and emit its own
receipt.

### 5. CFG lifetime and schedule analysis

The analyzer consumes a normalized CFG with asynchronous entries, ordered lock
operations, lifetime resources and sites. It finds same-resource multi-free and
free/use overlaps, records lock handoffs, and synthesizes a deterministic
candidate schedule. Every candidate is labeled structural until runtime replay
shows the same object identity at the required sinks.

The target-lowering compiler maps a selected candidate and detailed schedule
to concrete classifiers, selectors, captures, counters, and symbol relations.
It emits a content-addressed plan consumed by the generic kprobe backend. This
removes handwritten controller constants, but it does not remove the need to
extract and verify target-specific binary facts. Automated fact extraction and
ranking remain research work.

### 6. Stock boundary capture and offline replay

The capture compiler keeps program order within each actor and accepts explicit
cross-actor `causes` edges. Unsynchronised timestamps remain metadata. Payloads
are digest-only unless a public synthetic record explicitly allows inline data.
The public example compiles and replays automatically; a concrete device
collector remains outside this release.

### 7. Multi-version differential analysis

Version manifests bind component hashes, ABI identities, and extracted facts.
The differential reports component additions/removals plus binary, ABI, symbol,
call-edge, and lifetime-candidate changes. This is necessary because a schedule
or candidate from one build cannot be assumed to exist in another build merely
because the product family name matches.

## Research contribution test

The platform should not be presented as a loose bundle of emulators and
fuzzers. Its proposed research contribution is the evidence-preserving path
between otherwise separate tools:

1. represent asynchronous observations as a partial order;
2. bind protocol semantics and binary lifetime sites to stable identities;
3. synthesize and replay candidate schedules without collapsing concurrency;
4. record environment and version drift explicitly; and
5. issue a receipt that limits which claims transfer.

The hypothesis is falsifiable. If causal traces and identity-bound schedules do
not improve reproduction stability, reduce false transfer across versions, or
make observer effects measurable compared with timestamp-only replay, the
platform does not establish its intended contribution.

## Evaluation gates

- **P1 — public reproducibility:** every public fixture passes from a clean
  checkout with deterministic digests.
- **P2 — parser breadth:** at least one byte-level public parser per transport
  family is fuzzed with comparable feature and fault metrics.
- **P3 — backend execution:** native-stack and controller plans have real,
  attested runners; contract-only plans do not satisfy this gate.
- **P4 — causal advantage:** partial-order replay is compared against
  timestamp-only and total-order baselines.
- **P5 — schedule value:** synthesized schedules outperform unguided timing
  search on seeded and independently sourced fixtures.
- **P6 — version transfer:** candidate persistence and disappearance are
  evaluated across multiple hash-pinned versions.
- **P7 — observer effect:** probe sets are ablated and their schedule/coverage
  perturbation is quantified.

Only P1 is targeted by the current public release. The checked-in mechanisms
create the measurement path for P2 through P7; they are not substitutes for
those experiments.

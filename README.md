# RehostRace

RehostRace is an experimental framework for preserving causal relationships while replaying asynchronous component boundaries. It separates six contracts that are often mixed together in rehosting prototypes:

1. a canonical partial-order event trace;
2. a boundary-to-action binding;
3. a hash-bound candidate-to-target lowering;
4. a deterministic lifetime schedule;
5. an explicit oracle over object identity and sinks; and
6. a machine-readable evidence receipt with a claim boundary.

The repository is intentionally a framework and public fixture suite. It contains no proprietary binaries, firmware, device captures, link keys, product manifests, unpublished vulnerability schedules, or claims about a commercial target.

## Quick start

Python 3.10 or newer is sufficient for the portable reference path:

```bash
make verify
```

This runs the unit tests, the generic lifetime pipeline, the seven-slice Bluetooth profile matrix, the deterministic parser-fuzzing fixture, capture-to-replay compilation, CFG lifetime analysis, version differential analysis, a fail-closed release audit, and a reproducible file manifest. Generated evidence is written under `out/` and is not release material.

The package may also be installed locally:

```bash
python3 -m pip install -e .
```

## What is demonstrated

- causal DAG validation and deterministic linearization;
- capture with explicit actors, resources, clocks, and payload disclosure rules;
- declarative schedule synthesis and boundary binding;
- same-object lifetime oracles over public observations;
- exhaustive gate-subset planning and result summarization;
- stateful Bluetooth host-boundary models for HCI, ACL, L2CAP, AVDTP, SDP, ATT, GATT, SMP, RFCOMM, AVRCP, HFP, A2DP, and LE Audio lifecycle events;
- a trusted protocol-pack registry: data manifests select only handlers explicitly registered by the application;
- bounded byte-level parsers for representative SMP, RFCOMM, AVRCP/AVCTP, HFP AT, A2DP RTP, and LE ISO framing;
- deterministic offline coverage-guided fuzzing with content-addressed corpus and findings;
- capture-bundle compilation that preserves actor order and explicit cross-actor causes without ordering unsynchronised clocks;
- normalized binary-CFG lifetime candidate discovery and schedule candidate synthesis;
- fail-closed lowering of a candidate, schedule, and target fact manifest into a data-only controller plan and C header;
- hash-pinned semantic differential analysis across target versions;
- data-only execution contracts for native host-stack and controller-firmware backends;
- evidence receipts that hash inputs and state allowed and forbidden claim transfer.

## What is not demonstrated

The public fixtures do not establish whole-system fidelity, controller or radio behavior, execution of a proprietary binary, reachability on a stock device, a vulnerability, exploitability, or code execution. The new profile packs are semantic lifecycle models, not complete wire decoders. The native-stack and controller plans are validated contracts; no backend execution is claimed. A receipt is evidence for only the dimensions and claims it states.

## Layout

- `sdk/python/rehostrace/` — trace, replay, schedule, oracle, search, and receipt SDK;
- `schemas/` — machine-readable contracts;
- `fixtures/platform/` — generic lifetime and deferred-work examples;
- `fixtures/bluetooth/` — public protocol packs and causal traces;
- `fixtures/capture/` — public boundary-capture input;
- `fixtures/cfg/` and `fixtures/differential/` — public analysis inputs;
- `fixtures/lowering/` — synthetic target-fact mappings for CFG-to-controller lowering;
- `fixtures/fuzz/` and `fixtures/harness/` — deterministic fuzz policy and backend contracts;
- `fixtures/*_driver/` — intentionally seeded Linux module fixtures;
- `controllers/` and `include/` — deterministic scheduling reference code and the generic lowered-plan kprobe backend;
- `tools/` — runnable demos, CLI, release audit, and manifest generator;
- `tests/` — contract, negative, and end-to-end tests.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/TARGET_LOWERING.md](docs/TARGET_LOWERING.md), [docs/FULL_BLUETOOTH_ROADMAP.md](docs/FULL_BLUETOOTH_ROADMAP.md), [docs/CLAIM_MODEL.md](docs/CLAIM_MODEL.md), and [docs/RELEASE_SCOPE.md](docs/RELEASE_SCOPE.md) before adapting the framework to a new target.

## Research status

This is a research prototype, not a security scanner and not a drop-in whole-system emulator. Its intended contribution is a reproducible evidence boundary for asynchronous rehosting experiments. New adapters should add capture semantics, replay actions, an oracle, and an explicit fidelity receipt instead of silently inheriting claims from another environment.

## License and security

The code is licensed under GPL-2.0-only. See [LICENSE](LICENSE). Please use private vulnerability reporting as described in [SECURITY.md](SECURITY.md), and follow [CONTRIBUTING.md](CONTRIBUTING.md) for fixture and evidence requirements.

# RehostRace

RehostRace is an experimental framework for preserving causal relationships while replaying asynchronous component boundaries. It separates five contracts that are often mixed together in rehosting prototypes:

1. a canonical partial-order event trace;
2. a boundary-to-action binding;
3. a deterministic lifetime schedule;
4. an explicit oracle over object identity and sinks; and
5. a machine-readable evidence receipt with a claim boundary.

The repository is intentionally a framework and public fixture suite. It contains no proprietary binaries, firmware, device captures, link keys, product manifests, unpublished vulnerability schedules, or claims about a commercial target.

## Quick start

Python 3.10 or newer is sufficient for the portable reference path:

```bash
make verify
```

This runs the unit tests, the generic lifetime pipeline, the stateful HCI/ACL/L2CAP/AVDTP example, the Classic/LE profile matrix, a fail-closed release audit, and a reproducible file manifest. Generated evidence is written under `out/` and is not release material.

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
- stateful Bluetooth host-boundary models for HCI, ACL, L2CAP, AVDTP, SDP, ATT, and GATT;
- evidence receipts that hash inputs and state allowed and forbidden claim transfer.

## What is not demonstrated

The public fixtures do not establish whole-system fidelity, controller or radio behavior, execution of a proprietary binary, reachability on a stock device, a vulnerability, exploitability, or code execution. A receipt is evidence for only the dimensions and claims it states.

## Layout

- `sdk/python/rehostrace/` — trace, replay, schedule, oracle, search, and receipt SDK;
- `schemas/` — machine-readable contracts;
- `fixtures/platform/` — generic lifetime and deferred-work examples;
- `fixtures/bluetooth/` — public protocol packs and causal traces;
- `fixtures/*_driver/` — intentionally seeded Linux module fixtures;
- `controllers/` and `include/` — deterministic scheduling reference code;
- `tools/` — runnable demos, CLI, release audit, and manifest generator;
- `tests/` — contract, negative, and end-to-end tests.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/CLAIM_MODEL.md](docs/CLAIM_MODEL.md), and [docs/RELEASE_SCOPE.md](docs/RELEASE_SCOPE.md) before adapting the framework to a new target.

## Research status

This is a research prototype, not a security scanner and not a drop-in whole-system emulator. Its intended contribution is a reproducible evidence boundary for asynchronous rehosting experiments. New adapters should add capture semantics, replay actions, an oracle, and an explicit fidelity receipt instead of silently inheriting claims from another environment.

## License and security

The code is licensed under GPL-2.0-only. See [LICENSE](LICENSE). Please use private vulnerability reporting as described in [SECURITY.md](SECURITY.md), and follow [CONTRIBUTING.md](CONTRIBUTING.md) for fixture and evidence requirements.

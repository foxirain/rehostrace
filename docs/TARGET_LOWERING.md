# CFG-to-controller lowering

Target lowering turns a structural lifetime candidate into a concrete,
hash-bound controller configuration. It closes the gap between “these two CFG
paths can reach the same lifetime sink” and “these exact runtime locations must
be classified, observed, and scheduled.”

```text
normalized CFG --analyze--> lifetime candidates --synthesize--> candidate schedule
       |                                                        |
       +---------------- target fact manifest ------------------+
                                |
                     detailed semantic schedule
                                |
                                v
                     controller-plan/v1 + C header
```

## Inputs

The compiler consumes four independent documents:

1. a normalized CFG analysis with a self-hash;
2. synthesized candidate schedules bound to that analysis;
3. a detailed semantic schedule containing gates, signals, waits, counters,
   and the object-identity policy; and
4. a target lowering manifest containing the binary hash, architecture,
   runtime role classifiers, concrete hook selectors, identity captures,
   instruction-byte hashes, and optional symbol-distance invariants.

The first three describe *what* execution must be controlled. The target
manifest states *where and how* that meaning is represented in one pinned
binary. Keeping those layers separate lets reviewers distinguish automated
analysis from target-specific reverse-engineering facts.

## Fail-closed checks

`compile_target_controller()` rejects the lowering when any of these drift:

- CFG analysis or schedule-candidate integrity hash;
- selected candidate or detailed schedule identity;
- target binary hash or architecture;
- candidate-path coverage by runtime roles;
- detailed-schedule coverage by concrete point bindings;
- selector alignment and the presence and format of instruction-byte evidence;
- identity-capture ABI constraints; or
- same-object requirements between the candidate and detailed schedule.

The result is `rehostrace.controller-plan/v1`. Its `plan_sha256` covers every
field except itself. `render_target_controller_header()` refuses a plan whose
hash no longer verifies and emits data only: symbols, offsets, predicates,
capture locations, masks, counters, relations, and provenance hashes.

`controllers/target_lowered/` is the generic Linux kprobe consumer for that
header. At module load it resolves and checks symbol-distance relations before
arming any schedule point. During a single-shot run it classifies the runtime
roles, captures identity from the declared argument or AArch64 register,
enforces waits and releases, counts lifetime sinks, logs observers, and reports
the controller plan hash. A target integration must still bind the built
controller and actual target artifact hashes in its evidence receipt.

The portable compiler does not open the target binary, so it cannot itself
prove that an expected instruction hash matches bytes on disk. A target
integration must perform that comparison before building the controller and
record the result. The public manifest deliberately demonstrates this contract
with synthetic hashes; it is not binary verification evidence.

## Automation boundary

The following parts are automated:

- structural lifetime candidate discovery after CFG normalization;
- candidate schedule synthesis;
- consistency and integrity validation;
- conversion to backend-neutral controller records; and
- deterministic C-header rendering.

The following parts are not yet inferred automatically:

- recovering a high-fidelity CFG from every stripped binary;
- deciding which runtime arguments identify a semantic role;
- proving which register or argument carries the object at each instruction;
- choosing safe probe sites; and
- deriving all symbol relations from arbitrary binary formats.

Those facts must currently be supplied by an extractor or a reviewer and are
made auditable in the target manifest. This is intentional: missing binary
facts cause refusal instead of silently becoming guessed controller code.

## Public example

Run the synthetic lowering fixture with:

```bash
make target-lowering
```

The command writes the analysis, candidate set, controller plan, and generated
header under `out/target_lowering/`. The public fixture uses synthetic names
and hashes. It demonstrates the lowering mechanism only; it does not execute a
kernel module or establish a vulnerability in another target.

For a new integration, keep non-redistributable binaries, extracted facts,
and unpublished schedules outside this repository. Only promote a result from
mechanism evidence to target-path evidence after the generated plan is bound
to a built controller and the executing runtime reports the same plan hash.

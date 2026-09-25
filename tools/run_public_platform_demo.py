#!/usr/bin/env python3
"""Run the fully public causal-trace -> replay -> oracle -> receipt pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (  # noqa: E402
    CausalTrace,
    RecordingAdapter,
    ReplayEngine,
    build_receipt,
    compile_binding,
    compile_schedule,
    evaluate_oracle,
    render_c_header,
    render_binding_header,
    synthesize_schedule,
)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out/platform_demo")
    args = parser.parse_args()
    output = args.output.resolve()

    trace_path = ROOT / "fixtures/platform/async_boundary.causal.json"
    schedule_path = ROOT / "fixtures/platform/seeded_lifetime.schedule.json"
    constraints_path = ROOT / "fixtures/platform/seeded_lifetime.constraints.json"
    oracle_path = ROOT / "fixtures/platform/seeded_lifetime.oracle.json"
    observations_path = ROOT / "fixtures/platform/seeded_observations.jsonl"
    binding_path = ROOT / "fixtures/platform/seeded_boundary.binding.json"

    trace = CausalTrace(read_json(trace_path))
    replay = ReplayEngine(trace, RecordingAdapter()).run()
    schedule = read_json(schedule_path)
    synthesized_schedule, synthesis_report = synthesize_schedule(read_json(constraints_path))
    if synthesized_schedule != schedule:
        raise ValueError("synthesized schedule differs from checked-in schedule")
    plan = compile_schedule(schedule)
    binding = read_json(binding_path)
    binding_plan = compile_binding(binding, trace, schedule)
    oracle = read_json(oracle_path)
    observations = [
        json.loads(line)
        for line in observations_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    verdict = evaluate_oracle(oracle, observations)

    write_json(output / "trace-validation.json", trace.validation)
    write_json(output / "replay.json", replay)
    write_json(output / "schedule-plan.json", plan)
    write_json(output / "synthesized-schedule.json", synthesized_schedule)
    write_json(output / "schedule-synthesis-report.json", synthesis_report)
    write_json(output / "boundary-binding-plan.json", binding_plan)
    (output / "rehostrace_schedule_generated.h").write_text(
        render_c_header(schedule), encoding="utf-8"
    )
    (output / "rehostrace_boundary_binding_generated.h").write_text(
        render_binding_header(binding, trace, schedule), encoding="utf-8"
    )
    write_json(output / "oracle-result.json", verdict)

    status = "passed" if replay["status"] == "passed" and verdict["verdict"] == "positive" else "failed"
    receipt = build_receipt(
        receipt_id="public.platform-demo.v1",
        experiment="Public causality-preserving replay and lifetime-evidence pipeline",
        status=status,
        root=ROOT,
        inputs=[
            {"role": "causal-trace", "path": trace_path, "disclosure": "public"},
            {"role": "lifetime-schedule", "path": schedule_path, "disclosure": "public"},
            {"role": "schedule-constraints", "path": constraints_path, "disclosure": "public"},
            {"role": "lifetime-oracle", "path": oracle_path, "disclosure": "public"},
            {"role": "observations", "path": observations_path, "disclosure": "public"},
            {"role": "boundary-binding", "path": binding_path, "disclosure": "public"},
            {"role": "sdk-binding", "path": ROOT / "sdk/python/rehostrace/binding.py", "disclosure": "public"},
            {"role": "sdk-model", "path": ROOT / "sdk/python/rehostrace/model.py", "disclosure": "public"},
            {"role": "sdk-replay", "path": ROOT / "sdk/python/rehostrace/replay.py", "disclosure": "public"},
            {"role": "sdk-schedule", "path": ROOT / "sdk/python/rehostrace/schedule.py", "disclosure": "public"},
            {"role": "sdk-synthesis", "path": ROOT / "sdk/python/rehostrace/synthesis.py", "disclosure": "public"},
            {"role": "sdk-oracle", "path": ROOT / "sdk/python/rehostrace/oracle.py", "disclosure": "public"},
            {"role": "sdk-receipt", "path": ROOT / "sdk/python/rehostrace/receipt.py", "disclosure": "public"},
            {"role": "experiment-runner", "path": ROOT / "tools/run_public_platform_demo.py", "disclosure": "public"},
        ],
        execution={
            "architecture": "portable-model",
            "executor": "rehostrace-python-sdk",
            "event_order": replay["event_order"],
            "trace_sha256": trace.digest,
            "schedule_sha256": plan["source_sha256"],
            "constraints_sha256": synthesis_report["constraints_sha256"],
            "schedule_synthesis_match": True,
            "binding_sha256": binding_plan["binding_sha256"],
            "projected_events": [item["event_id"] for item in binding_plan["actions"]],
        },
        oracle=verdict,
        fidelity={
            "track": "public.synthetic.model",
            "dimensions": {
                "explicit_causal_order": "demonstrated",
                "offline_boundary_replay": "demonstrated",
                "declarative_lifetime_schedule": "demonstrated",
                "constraint_schedule_synthesis": "demonstrated",
                "object_identity_oracle": "demonstrated",
                "arm64_execution": "not-run",
                "exact_vendor_binary": "not-applicable",
                "stock_harmful_consequence": "not-applicable"
            },
            "transfer": {
                "allowed_claims": [
                    "artifact.reproducibility",
                    "mechanism.causal-replay",
                    "mechanism.schedule-compilation",
                    "mechanism.schedule-synthesis"
                ],
                "forbidden_claims": [
                    "finding.same-object-lifetime",
                    "target.exact-binary-path",
                    "target.vendor-vulnerability",
                    "stock.remote-reachability",
                    "stock.harmful-consequence",
                    "stock.race-probability",
                    "impact.exploitability",
                    "impact.code-execution"
                ],
                "asserted_claims": [
                    "artifact.reproducibility",
                    "mechanism.causal-replay",
                    "mechanism.schedule-compilation",
                    "mechanism.schedule-synthesis"
                ]
            }
        },
        claim_boundary=(
            "This receipt validates the public platform contracts and reference pipeline only. "
            "The observation stream is a synthetic fixture, not an ARM64 execution or product capture."
        ),
    )
    write_json(output / "evidence-receipt.json", receipt)
    print(
        json.dumps(
            {
                "status": status,
                "trace_sha256": trace.digest,
                "schedule_sha256": plan["source_sha256"],
                "receipt_sha256": receipt["integrity"]["content_sha256"],
                "output": str(output),
            },
            sort_keys=True,
        )
    )
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

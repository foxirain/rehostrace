#!/usr/bin/env python3
"""Dependency-free command line interface for the public RehostRace SDK."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (  # noqa: E402
    BluetoothCoreAdapter,
    CausalTrace,
    RecordingAdapter,
    ReplayEngine,
    analyze_lifetime_cfg,
    compile_ablation,
    compile_binding,
    compile_evidence_transfer_bridge,
    compile_observer_calibration,
    compile_schedule,
    compile_target_controller,
    default_bluetooth_registrations,
    evaluate_oracle,
    plan_exhaustive_search,
    render_c_header,
    render_target_controller_header,
    render_ablation_header,
    render_binding_header,
    synthesize_schedule,
    synthesize_lifetime_schedules,
    summarize_search,
    validate_receipt,
    validate_trace,
    verify_receipt_artifacts,
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path | None, document: dict) -> None:
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(rendered, end="")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate-trace")
    validate_parser.add_argument("trace", type=Path)
    validate_parser.add_argument("--output", type=Path)

    replay_parser = subparsers.add_parser("replay-plan")
    replay_parser.add_argument("trace", type=Path)
    replay_parser.add_argument("--order", help="comma-separated linear extension")
    replay_parser.add_argument("--output", type=Path)

    bluetooth_parser = subparsers.add_parser("replay-bluetooth")
    bluetooth_parser.add_argument("trace", type=Path)
    bluetooth_parser.add_argument(
        "--pack", action="append", required=True, type=Path,
        help="protocol-pack manifest; repeat in dependency order",
    )
    bluetooth_parser.add_argument("--output", type=Path)

    schedule_parser = subparsers.add_parser("compile-schedule")
    schedule_parser.add_argument("schedule", type=Path)
    schedule_parser.add_argument("--plan", required=True, type=Path)
    schedule_parser.add_argument("--header", required=True, type=Path)

    synthesis_parser = subparsers.add_parser("synthesize-schedule")
    synthesis_parser.add_argument("constraints", type=Path)
    synthesis_parser.add_argument("--output", required=True, type=Path)
    synthesis_parser.add_argument("--report", required=True, type=Path)
    synthesis_parser.add_argument(
        "--expect",
        type=Path,
        help="fail unless the synthesized document equals this checked-in schedule",
    )

    lowering_parser = subparsers.add_parser("lower-controller")
    lowering_parser.add_argument("cfg", type=Path)
    lowering_parser.add_argument("schedule", type=Path)
    lowering_parser.add_argument("target", type=Path)
    lowering_parser.add_argument("--analysis", required=True, type=Path)
    lowering_parser.add_argument("--candidates", required=True, type=Path)
    lowering_parser.add_argument("--plan", required=True, type=Path)
    lowering_parser.add_argument("--header", required=True, type=Path)

    search_parser = subparsers.add_parser("plan-schedule-search")
    search_parser.add_argument("constraints", type=Path)
    search_parser.add_argument("binding", type=Path)
    search_parser.add_argument("trace", type=Path)
    search_parser.add_argument("--search-id", required=True)
    search_parser.add_argument("--repetitions", required=True, type=int)
    search_parser.add_argument("--output-dir", required=True, type=Path)

    search_summary_parser = subparsers.add_parser("summarize-schedule-search")
    search_summary_parser.add_argument("manifest", type=Path)
    search_summary_parser.add_argument("trials", type=Path)
    search_summary_parser.add_argument("--output", required=True, type=Path)

    binding_parser = subparsers.add_parser("compile-binding")
    binding_parser.add_argument("trace", type=Path)
    binding_parser.add_argument("binding", type=Path)
    binding_parser.add_argument("--schedule", required=True, type=Path)
    binding_parser.add_argument("--plan", required=True, type=Path)
    binding_parser.add_argument("--header", required=True, type=Path)

    ablation_parser = subparsers.add_parser("compile-ablation")
    ablation_parser.add_argument("trace", type=Path)
    ablation_parser.add_argument("binding", type=Path)
    ablation_parser.add_argument("ablation", type=Path)
    ablation_parser.add_argument("--schedule", required=True, type=Path)
    ablation_parser.add_argument("--policy", required=True)
    ablation_parser.add_argument("--plan", required=True, type=Path)
    ablation_parser.add_argument("--header", required=True, type=Path)

    oracle_parser = subparsers.add_parser("evaluate-oracle")
    oracle_parser.add_argument("oracle", type=Path)
    oracle_parser.add_argument("observations", type=Path)
    oracle_parser.add_argument("--output", type=Path)

    receipt_parser = subparsers.add_parser("validate-receipt")
    receipt_parser.add_argument("receipt", type=Path)

    verify_receipt_parser = subparsers.add_parser("verify-receipt")
    verify_receipt_parser.add_argument("receipt", type=Path)
    verify_receipt_parser.add_argument("--root", required=True, type=Path)
    verify_receipt_parser.add_argument("--require-private", action="store_true")

    bridge_parser = subparsers.add_parser("compile-evidence-bridge")
    bridge_parser.add_argument("policy", type=Path)
    bridge_parser.add_argument("trace", type=Path)
    bridge_parser.add_argument("single_receipt", type=Path)
    bridge_parser.add_argument("campaign_receipt", type=Path)
    bridge_parser.add_argument("campaign_result", type=Path)
    bridge_parser.add_argument("--root", required=True, type=Path)
    bridge_parser.add_argument("--output", required=True, type=Path)

    observer_parser = subparsers.add_parser("calibrate-observer-effect")
    observer_parser.add_argument("policy", type=Path)
    observer_parser.add_argument("training_report", type=Path)
    observer_parser.add_argument("holdout_report", type=Path)
    observer_parser.add_argument("--output", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "validate-trace":
        write_json(args.output, validate_trace(load_json(args.trace)))
    elif args.command == "replay-plan":
        trace = CausalTrace(load_json(args.trace))
        order = args.order.split(",") if args.order else None
        write_json(args.output, ReplayEngine(trace, RecordingAdapter()).run(order))
    elif args.command == "replay-bluetooth":
        trace = CausalTrace(load_json(args.trace))
        manifests = [load_json(path) for path in args.pack]
        adapter = BluetoothCoreAdapter(default_bluetooth_registrations(manifests))
        replay = ReplayEngine(trace, adapter).run()
        write_json(
            args.output,
            {"status": "passed", "replay": replay, "state_summary": adapter.summary()},
        )
    elif args.command == "compile-schedule":
        schedule = load_json(args.schedule)
        write_json(args.plan, compile_schedule(schedule))
        args.header.parent.mkdir(parents=True, exist_ok=True)
        args.header.write_text(render_c_header(schedule), encoding="utf-8")
        print(json.dumps({"status": "passed", "plan": str(args.plan), "header": str(args.header)}))
    elif args.command == "synthesize-schedule":
        schedule, report = synthesize_schedule(load_json(args.constraints))
        if args.expect is not None:
            expected = load_json(args.expect)
            if schedule != expected:
                raise ValueError(
                    f"synthesized schedule differs from checked-in schedule: {args.expect}"
                )
            report["expected_schedule"] = str(args.expect)
            report["expected_schedule_match"] = True
        write_json(args.output, schedule)
        write_json(args.report, report)
        print(
            json.dumps(
                {
                    "status": "passed",
                    "schedule": str(args.output),
                    "report": str(args.report),
                    "schedule_sha256": report["schedule_sha256"],
                },
                sort_keys=True,
            )
        )
    elif args.command == "lower-controller":
        analysis = analyze_lifetime_cfg(load_json(args.cfg))
        candidates = synthesize_lifetime_schedules(analysis)
        plan = compile_target_controller(
            analysis,
            candidates,
            load_json(args.schedule),
            load_json(args.target),
        )
        write_json(args.analysis, analysis)
        write_json(args.candidates, candidates)
        write_json(args.plan, plan)
        args.header.parent.mkdir(parents=True, exist_ok=True)
        args.header.write_text(render_target_controller_header(plan), encoding="utf-8")
        print(
            json.dumps(
                {
                    "status": "passed",
                    "candidate_id": plan["source"]["candidate_id"],
                    "plan_sha256": plan["plan_sha256"],
                    "plan": str(args.plan),
                    "header": str(args.header),
                },
                sort_keys=True,
            )
        )
    elif args.command == "plan-schedule-search":
        trace = CausalTrace(load_json(args.trace))
        manifest, documents = plan_exhaustive_search(
            load_json(args.constraints),
            load_json(args.binding),
            trace,
            search_id=args.search_id,
            repetitions=args.repetitions,
        )
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for candidate_id, candidate in documents.items():
            directory = args.output_dir / candidate_id
            write_json(directory / "constraints.json", candidate["constraints"])
            write_json(directory / "schedule.json", candidate["schedule"])
            write_json(directory / "binding.json", candidate["binding"])
            write_json(directory / "synthesis-report.json", candidate["synthesis"])
        manifest_path = args.output_dir / "manifest.json"
        write_json(manifest_path, manifest)
        print(
            json.dumps(
                {
                    "status": "passed",
                    "candidate_count": len(manifest["candidates"]),
                    "manifest": str(manifest_path),
                },
                sort_keys=True,
            )
        )
    elif args.command == "summarize-schedule-search":
        result = summarize_search(load_json(args.manifest), load_jsonl(args.trials))
        write_json(args.output, result)
        print(
            json.dumps(
                {
                    "status": result["status"],
                    "candidate_count": result["candidate_count"],
                    "trial_count": result["trial_count"],
                    "globally_minimal_gate_count": result[
                        "globally_minimal_gate_count"
                    ],
                    "output": str(args.output),
                },
                sort_keys=True,
            )
        )
    elif args.command == "compile-binding":
        trace = CausalTrace(load_json(args.trace))
        binding = load_json(args.binding)
        schedule = load_json(args.schedule)
        write_json(args.plan, compile_binding(binding, trace, schedule))
        args.header.parent.mkdir(parents=True, exist_ok=True)
        args.header.write_text(render_binding_header(binding, trace, schedule), encoding="utf-8")
        print(json.dumps({"status": "passed", "plan": str(args.plan), "header": str(args.header)}))
    elif args.command == "compile-ablation":
        trace = CausalTrace(load_json(args.trace))
        plan = compile_ablation(
            load_json(args.ablation), trace, load_json(args.binding), load_json(args.schedule)
        )
        write_json(args.plan, plan)
        args.header.parent.mkdir(parents=True, exist_ok=True)
        args.header.write_text(render_ablation_header(plan, args.policy), encoding="utf-8")
        print(
            json.dumps(
                {
                    "status": "passed",
                    "policy": args.policy,
                    "plan": str(args.plan),
                    "header": str(args.header),
                },
                sort_keys=True,
            )
        )
    elif args.command == "evaluate-oracle":
        write_json(args.output, evaluate_oracle(load_json(args.oracle), load_jsonl(args.observations)))
    elif args.command == "validate-receipt":
        write_json(None, validate_receipt(load_json(args.receipt)))
    elif args.command == "verify-receipt":
        write_json(
            None,
            verify_receipt_artifacts(
                load_json(args.receipt), args.root, require_private=args.require_private
            ),
        )
    elif args.command == "compile-evidence-bridge":
        single = load_json(args.single_receipt)
        campaign = load_json(args.campaign_receipt)
        verify_receipt_artifacts(single, args.root)
        verify_receipt_artifacts(campaign, args.root)
        result_bytes = args.campaign_result.read_bytes()
        bridge = compile_evidence_transfer_bridge(
            load_json(args.policy),
            CausalTrace(load_json(args.trace)),
            single,
            campaign,
            json.loads(result_bytes),
            campaign_result_sha256=hashlib.sha256(result_bytes).hexdigest(),
        )
        write_json(args.output, bridge)
        print(
            json.dumps(
                {
                    "status": bridge["status"],
                    "bridge_id": bridge["bridge_id"],
                    "verified_runs": bridge["lifetime_evidence"]["verified_runs"],
                    "content_sha256": bridge["integrity"]["content_sha256"],
                    "output": str(args.output),
                },
                sort_keys=True,
            )
        )
    elif args.command == "calibrate-observer-effect":
        training_bytes = args.training_report.read_bytes()
        holdout_bytes = args.holdout_report.read_bytes()
        result = compile_observer_calibration(
            load_json(args.policy),
            json.loads(training_bytes),
            json.loads(holdout_bytes),
            training_report_sha256=hashlib.sha256(training_bytes).hexdigest(),
            holdout_report_sha256=hashlib.sha256(holdout_bytes).hexdigest(),
        )
        write_json(args.output, result)
        print(
            json.dumps(
                {
                    "status": result["status"],
                    "calibration_id": result["calibration_id"],
                    "predicted_unobserved_rate": result["holdout"][
                        "predicted_unobserved_rate"
                    ],
                    "actual_unobserved_rate": result["holdout"]["observer_off"]["rate"],
                    "absolute_error": result["holdout"]["absolute_error"],
                    "content_sha256": result["integrity"]["content_sha256"],
                    "output": str(args.output),
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

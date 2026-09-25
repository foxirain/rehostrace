#!/usr/bin/env python3
"""Run public CFG, schedule, differential, and harness-contract demos."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import analyze_lifetime_cfg, compare_target_manifests, compile_harness_plan, synthesize_lifetime_schedules  # noqa: E402


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def write(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out/analysis_pipeline")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    analysis = analyze_lifetime_cfg(read(ROOT / "fixtures/cfg/lock_handoff.graph.json"))
    schedules = synthesize_lifetime_schedules(analysis)
    differential = compare_target_manifests(read(ROOT / "fixtures/differential/target_v1.json"), read(ROOT / "fixtures/differential/target_v2.json"))
    native = compile_harness_plan(read(ROOT / "fixtures/harness/android_native.plan.json"))
    controller = compile_harness_plan(read(ROOT / "fixtures/harness/controller_firmware.plan.json"))
    for name, value in (("lifetime-analysis", analysis), ("schedule-candidates", schedules), ("target-differential", differential), ("android-native-execution", native), ("controller-execution", controller)):
        write(args.output / f"{name}.json", value)
    status = "passed" if analysis["candidate_count"] >= 1 and schedules["schedules"] and differential["changes"] and not native["executable"] and not controller["executable"] else "failed"
    print(json.dumps({"status": status, "lifetime_candidates": analysis["candidate_count"], "schedules": len(schedules["schedules"]), "version_changes": len(differential["changes"]), "output": str(args.output)}, sort_keys=True))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

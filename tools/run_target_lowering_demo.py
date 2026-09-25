#!/usr/bin/env python3
"""Run the public CFG-to-controller lowering example."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (  # noqa: E402
    analyze_lifetime_cfg,
    compile_target_controller,
    render_target_controller_header,
    synthesize_lifetime_schedules,
)


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out/target_lowering")
    args = parser.parse_args()
    analysis = analyze_lifetime_cfg(read(ROOT / "fixtures/cfg/lock_handoff.graph.json"))
    candidates = synthesize_lifetime_schedules(analysis)
    schedule = read(ROOT / "fixtures/platform/seeded_lifetime.schedule.json")
    lowering = read(ROOT / "fixtures/lowering/public_seeded.target.json")
    plan = compile_target_controller(analysis, candidates, schedule, lowering)
    write(args.output / "lifetime-analysis.json", analysis)
    write(args.output / "schedule-candidates.json", candidates)
    write(args.output / "controller-plan.json", plan)
    (args.output / "rehostrace_target_lowered_generated.h").write_text(
        render_target_controller_header(plan), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": "passed",
                "candidate_id": plan["source"]["candidate_id"],
                "points": len(plan["points"]),
                "roles": len(plan["roles"]),
                "plan_sha256": plan["plan_sha256"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run the deterministic public parser fixture and emit a campaign report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import CoverageGuidedFuzzer, FuzzOutcome  # noqa: E402


def public_parser(data: bytes) -> FuzzOutcome:
    features = set()
    if data.startswith(b"BT"):
        features.add("magic")
    else:
        return FuzzOutcome("reject", frozenset({"bad-magic"}))
    if len(data) >= 3:
        features.add("header-complete")
        if data[2] == 0xFF:
            features.add("seeded-fault-edge")
            return FuzzOutcome("crash", frozenset(features), "public seeded oracle")
        features.add(f"type:{data[2] & 3}")
    return FuzzOutcome("ok", frozenset(features))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out/fuzz/public-campaign.json")
    args = parser.parse_args()
    policy = json.loads((ROOT / "fixtures/fuzz/public_parser.policy.json").read_text())
    report = CoverageGuidedFuzzer(policy, public_parser).run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"executions": report["executions"], "features": len(report["features"]), "findings": len(report["findings"]), "output": str(args.output)}, sort_keys=True))
    return 0 if any(item["kind"] == "crash" for item in report["findings"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())

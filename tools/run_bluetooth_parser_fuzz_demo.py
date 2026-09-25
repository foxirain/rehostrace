#!/usr/bin/env python3
"""Fuzz all six public bounded Bluetooth packet parsers offline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (  # noqa: E402
    CoverageGuidedFuzzer,
    FuzzOutcome,
    PacketParseError,
    built_in_packet_parser_registry,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out/fuzz/bluetooth-parsers")
    args = parser.parse_args()
    policy_set = json.loads((ROOT / "fixtures/fuzz/bluetooth_parsers.campaigns.json").read_text())
    if policy_set.get("schema_version") != "rehostrace.fuzz-campaign-set/v1":
        raise ValueError("unsupported campaign-set schema")
    registry = built_in_packet_parser_registry()
    reports = []
    args.output.mkdir(parents=True, exist_ok=True)
    for document in policy_set["campaigns"]:
        protocol = document["protocol"]
        policy = {key: value for key, value in document.items() if key != "protocol"}

        def target(data: bytes, selected: str = protocol) -> FuzzOutcome:
            try:
                parsed = registry.parse(selected, data)
                return FuzzOutcome("ok", parsed.features)
            except PacketParseError as error:
                return FuzzOutcome("reject", frozenset({f"{selected}:reject:{error}"}))

        report = CoverageGuidedFuzzer(policy, target).run()
        (args.output / f"{protocol}.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        reports.append(
            {
                "protocol": protocol,
                "campaign_id": report["campaign_id"],
                "report_sha256": report["report_sha256"],
                "executions": report["executions"],
                "features": len(report["features"]),
                "accepted": report["status_counts"]["ok"],
                "rejected": report["status_counts"]["reject"],
                "faults": len(report["findings"]),
            }
        )
    summary = {
        "schema_version": "rehostrace.bluetooth-parser-fuzz-matrix/v1",
        "status": "passed" if len(reports) == 6 and all(item["executions"] > 0 and item["features"] > 0 and item["accepted"] > 0 for item in reports) else "failed",
        "campaigns": reports,
        "claim_boundary": "These are bounded public parser campaigns, not production-stack coverage or vulnerability findings."
    }
    (args.output / "matrix.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": summary["status"], "campaigns": len(reports), "executions": sum(item["executions"] for item in reports), "features": sum(item["features"] for item in reports), "faults": sum(item["faults"] for item in reports), "output": str(args.output)}, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

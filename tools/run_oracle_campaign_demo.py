#!/usr/bin/env python3
"""Run the public repeated-oracle campaign fixture."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import summarize_oracle_campaign  # noqa: E402


def main() -> int:
    policy = json.loads(
        (ROOT / "fixtures/platform/target_owned_reclaim.campaign.json").read_text(
            encoding="utf-8"
        )
    )
    trials = [
        json.loads(line)
        for line in (
            ROOT / "fixtures/platform/target_owned_reclaim.campaign.runs.jsonl"
        )
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    result = summarize_oracle_campaign(policy, trials)
    output = ROOT / "out/oracle_campaign/campaign-result.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "outcomes": result["outcomes"],
                "output": str(output.relative_to(ROOT)),
            },
            sort_keys=True,
        )
    )
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

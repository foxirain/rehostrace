#!/usr/bin/env python3
"""Run the public target-owned reclaim provenance fixture."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import build_receipt, evaluate_reclaim_oracle  # noqa: E402


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    oracle_path = ROOT / "fixtures/platform/target_owned_reclaim.oracle.json"
    observations_path = ROOT / "fixtures/platform/target_owned_reclaim.observations.jsonl"
    output = ROOT / "out/reclaim_provenance"
    result = evaluate_reclaim_oracle(load_json(oracle_path), load_jsonl(observations_path))
    write_json(output / "oracle-result.json", result)

    status = "passed" if result["verdict"] == "positive" else result["verdict"]
    receipt = build_receipt(
        receipt_id="public.target-owned-reclaim.receipt.v1",
        experiment="Public target-owned reclaim provenance fixture",
        status=status,
        root=ROOT,
        inputs=[
            {"role": "reclaim-oracle", "path": oracle_path, "disclosure": "public"},
            {
                "role": "reclaim-observations",
                "path": observations_path,
                "disclosure": "public",
            },
        ],
        execution={
            "architecture": "portable-model",
            "executor": "rehostrace-reclaim-oracle",
            "event_order": [
                "original.free",
                "boundary.input",
                "replacement.alloc",
                "stale.read",
                "list.write",
                "foreign.free",
                "alias.alloc",
            ],
            "replacement_producer": result["replacement_producer"],
            "replacement_origin_event": result["replacement_origin_event"],
        },
        oracle=result,
        fidelity={
            "track": "public.synthetic.reclaim",
            "dimensions": {
                "allocation-provenance": "demonstrated",
                "same-address-reuse": "demonstrated",
                "foreign-owner-free": "demonstrated",
                "product-path": "not-applicable",
                "stock": "not-applicable",
            },
            "transfer": {
                "allowed_claims": [
                    "artifact.reproducibility",
                    "mechanism.allocation-provenance",
                    "finding.foreign-owner-free",
                ],
                "forbidden_claims": [
                    "target.vendor-vulnerability",
                    "stock.remote-reachability",
                    "stock.harmful-consequence",
                    "impact.exploitability",
                    "impact.code-execution",
                ],
                "asserted_claims": [
                    "artifact.reproducibility",
                    "mechanism.allocation-provenance",
                    "finding.foreign-owner-free",
                ],
            },
        },
        claim_boundary=(
            "The receipt demonstrates the allocation-provenance and foreign-owner-free "
            "contracts on public synthetic tokens. It makes no product, stock-device, or "
            "exploitability claim."
        ),
    )
    write_json(output / "evidence-receipt.json", receipt)
    print(
        json.dumps(
            {
                "status": status,
                "verdict": result["verdict"],
                "checks": len(result["checks"]),
                "receipt": str(output / "evidence-receipt.json"),
            },
            sort_keys=True,
        )
    )
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

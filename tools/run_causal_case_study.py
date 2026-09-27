#!/usr/bin/env python3
"""Build the public causal-DAG versus naive-timestamp case study."""

from __future__ import annotations

import argparse
import copy
import hashlib
import itertools
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import CausalTrace, compile_ablation


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def content_sha256(document: dict) -> str:
    material = copy.deepcopy(document)
    material.pop("integrity", None)
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def build_case_study(root: Path = ROOT) -> dict:
    trace = CausalTrace(load_json(root / "fixtures/platform/async_boundary.causal.json"))
    binding = load_json(root / "fixtures/platform/seeded_boundary.nogate.binding.json")
    schedule = load_json(root / "fixtures/platform/seeded_lifetime.nogate.schedule.json")
    ablation = load_json(root / "fixtures/platform/causal_order.ablation.json")
    plan = compile_ablation(ablation, trace, binding, schedule)

    action_event = {action["id"]: action["event_id"] for action in binding["actions"]}
    actions = plan["actions"]
    if len(actions) != 2:
        raise ValueError("the public case study requires exactly two projected actions")
    first_event, second_event = (action_event[action] for action in actions)
    if not trace.concurrent(first_event, second_event):
        raise ValueError("the public case-study events are no longer concurrent")

    legal_orders = [
        list(order)
        for order in itertools.permutations(actions)
    ]
    policies = {record["id"]: record for record in plan["policies"]}
    causal = policies["causal-dag"]
    naive = policies["naive-timestamp"]
    if not causal["preserves_concurrency"] or not naive["cross_domain_timestamp_comparison"]:
        raise ValueError("the ablation no longer demonstrates the intended information loss")
    if naive["action_order"] not in legal_orders:
        raise ValueError("the timestamp baseline selected an invalid projected order")
    discarded = [order for order in legal_orders if order != naive["action_order"]]

    pair = []
    for action_id in actions:
        event = trace.events[action_event[action_id]]
        pair.append(
            {
                "action_id": action_id,
                "event_id": event["id"],
                "operation": event["boundary"]["operation"],
                "clock_domain": event["clock"]["domain"],
                "clock_value": event["clock"]["value"],
            }
        )
    if len({record["clock_domain"] for record in pair}) != 2:
        raise ValueError("the public case study must compare distinct clock domains")

    result = {
        "schema_version": "rehostrace.causal-case-study/v1",
        "case_id": "public.concurrent-reset.causal-vs-timestamp",
        "sources": {
            "trace_id": trace.document["trace_id"],
            "trace_sha256": trace.digest,
            "ablation_id": plan["ablation_id"],
            "ablation_sha256": plan["ablation_sha256"],
            "binding_id": plan["binding_id"],
            "binding_sha256": plan["binding_sha256"],
        },
        "projected_pair": {
            "relation": "concurrent",
            "events": pair,
        },
        "causal_dag": {
            "preserves_concurrency": True,
            "candidate_action_orders": legal_orders,
            "candidate_order_count": len(legal_orders),
        },
        "naive_timestamp": {
            "cross_domain_comparison": True,
            "selected_action_order": naive["action_order"],
            "candidate_order_count": 1,
            "discarded_legal_orders": discarded,
            "discarded_order_count": len(discarded),
            "warning": naive["warning"],
        },
        "finding": (
            "A raw comparison of unsynchronised clock values discards one of two "
            "causally legal action orders before deterministic schedule search begins."
        ),
        "claim_boundary": (
            "This synthetic case demonstrates replay search-space preservation only. "
            "It does not establish a vulnerability, product reachability, or impact."
        ),
    }
    result["integrity"] = {"content_sha256": content_sha256(result)}
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "out/causal_case_study/case-study.json",
    )
    args = parser.parse_args()
    result = build_case_study()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "status": "passed",
                "output": str(args.output),
                "causal_orders": result["causal_dag"]["candidate_order_count"],
                "timestamp_orders": result["naive_timestamp"]["candidate_order_count"],
                "discarded_orders": result["naive_timestamp"]["discarded_order_count"],
                "content_sha256": result["integrity"]["content_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

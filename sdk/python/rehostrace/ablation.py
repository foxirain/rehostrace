"""Compile replay-order ablations without treating timestamps as causality."""

from __future__ import annotations

import copy
import hashlib
import json
import re

from .binding import compile_binding
from .model import CausalTrace, ID_RE, SHA256_RE


POLICY_KINDS = {"causal-dag", "fixed-total-order", "naive-timestamp"}


def _digest(document: dict) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_action_order(order: object, action_ids: set[str], policy_id: str) -> list[str]:
    if (
        not isinstance(order, list)
        or len(order) != len(action_ids)
        or len(order) != len(set(order))
        or set(order) != action_ids
    ):
        raise ValueError(f"policy {policy_id} must totally order every bound action exactly once")
    return list(order)


def _mode_for(order: list[str], canonical_actions: list[str]) -> int:
    if order == canonical_actions:
        return 1
    if order == list(reversed(canonical_actions)):
        return 2
    raise ValueError("the public ARM64 ablation fixture currently supports exactly two actions")


def compile_ablation(
    document: dict,
    trace: CausalTrace,
    binding: dict,
    schedule: dict,
) -> dict:
    """Validate and compile replay policies for one hash-bound two-action projection.

    The naive timestamp policy is deliberately labelled unsound whenever it
    compares unsynchronised clock domains.  It is retained only as a baseline
    whose information loss can be measured, never as a causal reconstruction.
    """

    if (
        not isinstance(document, dict)
        or document.get("schema_version") != "rehostrace.replay-ablation/v1"
    ):
        raise ValueError("invalid replay-ablation schema_version")
    ablation_id = document.get("ablation_id")
    if not isinstance(ablation_id, str) or not ID_RE.fullmatch(ablation_id):
        raise ValueError("invalid ablation_id")
    if document.get("trace_sha256") != trace.digest:
        raise ValueError("ablation trace_sha256 does not match the causal trace")
    binding_plan = compile_binding(binding, trace, schedule)
    if document.get("binding_sha256") != binding_plan["binding_sha256"]:
        raise ValueError("ablation binding_sha256 does not match the boundary binding")
    if not isinstance(document.get("claim_boundary"), str) or not document["claim_boundary"]:
        raise ValueError("ablation claim_boundary must be non-empty")

    action_by_id = {record["id"]: record for record in binding_plan["actions"]}
    canonical_actions = sorted(action_by_id)
    if len(canonical_actions) != 2:
        raise ValueError("replay-ablation/v1 requires exactly two projected actions")
    first_event = action_by_id[canonical_actions[0]]["event_id"]
    second_event = action_by_id[canonical_actions[1]]["event_id"]
    if not trace.concurrent(first_event, second_event):
        raise ValueError("the selected projection is not concurrent in the causal DAG")

    policies = document.get("policies")
    if not isinstance(policies, list) or not policies:
        raise ValueError("ablation policies must be a non-empty list")
    compiled: list[dict] = []
    seen: set[str] = set()
    for record in policies:
        policy_id = record.get("id") if isinstance(record, dict) else None
        kind = record.get("kind") if isinstance(record, dict) else None
        if (
            not isinstance(policy_id, str)
            or not ID_RE.fullmatch(policy_id)
            or policy_id in seen
        ):
            raise ValueError("ablation policy ids must be unique canonical ids")
        if kind not in POLICY_KINDS:
            raise ValueError(f"unsupported ablation policy kind: {kind}")
        seen.add(policy_id)
        if kind == "causal-dag":
            if "action_order" in record:
                raise ValueError("causal-dag policy cannot impose an action_order")
            compiled.append(
                {
                    "id": policy_id,
                    "kind": kind,
                    "mode": 0,
                    "action_order": [],
                    "event_order": [],
                    "preserves_concurrency": True,
                    "cross_domain_timestamp_comparison": False,
                }
            )
            continue

        if kind == "fixed-total-order":
            order = _validate_action_order(record.get("action_order"), set(canonical_actions), policy_id)
            compiled.append(
                {
                    "id": policy_id,
                    "kind": kind,
                    "mode": _mode_for(order, canonical_actions),
                    "action_order": order,
                    "event_order": [action_by_id[item]["event_id"] for item in order],
                    "preserves_concurrency": False,
                    "cross_domain_timestamp_comparison": False,
                }
            )
            continue

        if record.get("acknowledge_cross_domain_unsoundness") is not True:
            raise ValueError(
                f"policy {policy_id} must explicitly acknowledge cross-domain timestamp unsoundness"
            )
        timestamped: list[tuple[int, str, str, str]] = []
        domains: set[str] = set()
        for action_id in canonical_actions:
            event_id = action_by_id[action_id]["event_id"]
            event = trace.events[event_id]
            clock = event.get("clock")
            if not isinstance(clock, dict):
                raise ValueError(f"timestamp policy event lacks a clock: {event_id}")
            domain = clock["domain"]
            domains.add(domain)
            timestamped.append((clock["value"], event_id, action_id, domain))
        cross_domain = len(domains) > 1
        if not cross_domain:
            raise ValueError("naive-timestamp baseline requires distinct clock domains")
        order = [item[2] for item in sorted(timestamped)]
        compiled.append(
            {
                "id": policy_id,
                "kind": kind,
                "mode": _mode_for(order, canonical_actions),
                "action_order": order,
                "event_order": [action_by_id[item]["event_id"] for item in order],
                "preserves_concurrency": False,
                "cross_domain_timestamp_comparison": True,
                "clock_domains": sorted(domains),
                "warning": "raw values from unsynchronised clock domains are not a causal order",
            }
        )

    return {
        "schema_version": "rehostrace.replay-ablation-plan/v1",
        "ablation_id": ablation_id,
        "ablation_sha256": _digest(document),
        "trace_id": trace.document["trace_id"],
        "trace_sha256": trace.digest,
        "binding_id": binding_plan["binding_id"],
        "binding_sha256": binding_plan["binding_sha256"],
        "schedule_sha256": binding_plan["schedule_sha256"],
        "actions": canonical_actions,
        "policies": compiled,
        "claim_boundary": document["claim_boundary"],
    }


def render_ablation_header(plan: dict, policy_id: str) -> str:
    policy = next((record for record in plan["policies"] if record["id"] == policy_id), None)
    if policy is None:
        raise ValueError(f"unknown ablation policy: {policy_id}")

    def c_string(value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    return "\n".join(
        [
            "/* Generated by RehostRace. Do not edit. */",
            "#ifndef REHOSTRACE_REPLAY_ABLATION_GENERATED_H",
            "#define REHOSTRACE_REPLAY_ABLATION_GENERATED_H",
            f"#define REHOSTRACE_ABLATION_ID {c_string(plan['ablation_id'])}",
            f"#define REHOSTRACE_ABLATION_SHA256 {c_string(plan['ablation_sha256'])}",
            f"#define REHOSTRACE_ABLATION_POLICY_ID {c_string(policy['id'])}",
            f"#define REHOSTRACE_ABLATION_POLICY_KIND {c_string(policy['kind'])}",
            f"#define REHOSTRACE_ABLATION_MODE {policy['mode']}",
            f"#define REHOSTRACE_ABLATION_PRESERVES_CONCURRENCY {1 if policy['preserves_concurrency'] else 0}",
            f"#define REHOSTRACE_ABLATION_CROSS_DOMAIN_TIMESTAMP {1 if policy['cross_domain_timestamp_comparison'] else 0}",
            "#endif",
            "",
        ]
    )

"""Constraint-to-schedule synthesis for semantic lifetime milestones."""

from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict

from .model import ID_RE
from .schedule import CAPTURES, SELECTOR_KINDS, SYMBOL_RE, validate_schedule


def _digest(document: dict) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _topological(nodes: set[str], edges: set[tuple[str, str]]) -> list[str]:
    children: dict[str, set[str]] = defaultdict(set)
    indegree = {node: 0 for node in nodes}
    for before, after in edges:
        if before == after:
            raise ValueError(f"self-dependent phase: {before}")
        if after not in children[before]:
            children[before].add(after)
            indegree[after] += 1
    ready = sorted(node for node, degree in indegree.items() if degree == 0)
    result: list[str] = []
    while ready:
        node = ready.pop(0)
        result.append(node)
        for child in sorted(children[node]):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort()
    if len(result) != len(nodes):
        cyclic = sorted(node for node, degree in indegree.items() if degree)
        raise ValueError(f"constraint phase graph contains a cycle: {cyclic}")
    return result


def validate_constraints(document: dict) -> dict:
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != "rehostrace.schedule-constraints/v1"
    ):
        raise ValueError("invalid constraint schema_version")
    synthesis_id = _id(document.get("synthesis_id"), "synthesis_id")
    _id(document.get("schedule_id"), "schedule_id")
    if document.get("disclosure") not in {
        "public-synthetic",
        "private-product",
        "vendor-approved",
    }:
        raise ValueError("invalid constraint disclosure")
    timeout = document.get("timeout_ms")
    if type(timeout) is not int or not 1 <= timeout <= 600000:
        raise ValueError("constraint timeout_ms must be in [1, 600000]")
    identity = document.get("identity")
    if not isinstance(identity, dict) or identity.get("capture") not in CAPTURES or identity.get(
        "policy"
    ) not in {"same-across-points", "per-point", "none"}:
        raise ValueError("invalid constraint identity policy")
    if not isinstance(document.get("claim_boundary"), str) or not document["claim_boundary"]:
        raise ValueError("constraint claim_boundary must be non-empty")

    signal_order = document.get("signal_order")
    if (
        not isinstance(signal_order, list)
        or not 1 <= len(signal_order) <= 31
        or len(signal_order) != len(set(signal_order))
        or any(not isinstance(item, str) or not ID_RE.fullmatch(item) for item in signal_order)
    ):
        raise ValueError("signal_order must contain 1..31 unique canonical ids")
    signals = set(signal_order)

    point_list = document.get("points")
    if not isinstance(point_list, list) or not point_list:
        raise ValueError("constraints must contain points")
    points: dict[str, dict] = {}
    phase_nodes: set[str] = set()
    phase_edges: set[tuple[str, str]] = set()
    for record in point_list:
        point_id = _id(record.get("id") if isinstance(record, dict) else None, "point id")
        if point_id in points:
            raise ValueError(f"duplicate constraint point: {point_id}")
        selector = record.get("selector")
        if not isinstance(selector, dict) or selector.get("kind") not in SELECTOR_KINDS:
            raise ValueError(f"invalid constraint selector: {point_id}")
        if selector["kind"] in {"symbol", "tracepoint"} and (
            not isinstance(selector.get("symbol"), str)
            or not SYMBOL_RE.fullmatch(selector["symbol"])
        ):
            raise ValueError(f"invalid constraint selector symbol: {point_id}")
        points[point_id] = record
        enter, release = f"{point_id}:enter", f"{point_id}:release"
        phase_nodes.update((enter, release))
        phase_edges.add((enter, release))

    producers: dict[str, str] = {}
    milestone_list = document.get("milestones")
    if not isinstance(milestone_list, list):
        raise ValueError("milestones must be a list")
    for record in milestone_list:
        signal = _id(record.get("signal") if isinstance(record, dict) else None, "milestone signal")
        point = record.get("point")
        phase = record.get("phase")
        if signal not in signals or signal in producers:
            raise ValueError(f"unknown or duplicate milestone signal: {signal}")
        if point not in points or phase not in {"enter", "release"}:
            raise ValueError(f"invalid milestone producer: {signal}")
        producers[signal] = f"{point}:{phase}"

    point_counters: dict[str, str] = {}
    counter_ids: set[str] = set()
    counter_list = document.get("counters")
    if not isinstance(counter_list, list):
        raise ValueError("counters must be a list")
    for record in counter_list:
        counter_id = _id(record.get("id") if isinstance(record, dict) else None, "counter id")
        point = record.get("point")
        signal = record.get("emit_at_threshold")
        if counter_id in counter_ids or point not in points or point in point_counters:
            raise ValueError(f"duplicate or invalid counter: {counter_id}")
        if type(record.get("threshold")) is not int or record["threshold"] < 1:
            raise ValueError(f"invalid counter threshold: {counter_id}")
        if signal not in signals or signal in producers:
            raise ValueError(f"unknown or duplicate counter signal: {counter_id}")
        counter_ids.add(counter_id)
        point_counters[point] = counter_id
        producers[signal] = f"counter:{counter_id}"

    gate_list = document.get("gates")
    if not isinstance(gate_list, list):
        raise ValueError("gates must be a list")
    seen_gates: set[tuple[str, str]] = set()
    for record in gate_list:
        signal = record.get("after_signal") if isinstance(record, dict) else None
        target = record.get("before_release_of") if isinstance(record, dict) else None
        if signal not in producers or target not in points:
            raise ValueError(f"gate references an unknown producer or target: {signal}, {target}")
        gate = (signal, target)
        if gate in seen_gates:
            raise ValueError(f"duplicate gate: {signal}, {target}")
        seen_gates.add(gate)
        source_phase = producers[signal]
        if source_phase.startswith("counter:"):
            raise ValueError(
                f"counter-produced gate is not modeled by constraints/v1: {signal}, {target}"
            )
        phase_edges.add((source_phase, f"{target}:release"))

    missing = signals - set(producers)
    if missing:
        raise ValueError(f"signals without milestone/counter producers: {sorted(missing)}")
    phase_order = _topological(phase_nodes, phase_edges)
    return {
        "status": "passed",
        "synthesis_id": synthesis_id,
        "constraints_sha256": _digest(document),
        "point_count": len(points),
        "signal_count": len(signals),
        "gate_count": len(seen_gates),
        "phase_order": phase_order,
    }


def synthesize_schedule(document: dict) -> tuple[dict, dict]:
    validation = validate_constraints(document)
    enter_signals: dict[str, list[str]] = defaultdict(list)
    release_signals: dict[str, list[str]] = defaultdict(list)
    waits: dict[str, list[str]] = defaultdict(list)
    for record in document["milestones"]:
        target = enter_signals if record["phase"] == "enter" else release_signals
        target[record["point"]].append(record["signal"])
    for record in document["gates"]:
        waits[record["before_release_of"]].append(record["after_signal"])
    counter_by_point = {record["point"]: record for record in document["counters"]}

    point_records = []
    for point in document["points"]:
        record = {
            "id": point["id"],
            "selector": copy.deepcopy(point["selector"]),
            "emit_on_enter": enter_signals[point["id"]],
            "wait_for": waits[point["id"]],
            "emit_on_release": release_signals[point["id"]],
        }
        if point["id"] in counter_by_point:
            record["counter"] = counter_by_point[point["id"]]["id"]
        if "description" in point:
            record["description"] = point["description"]
        point_records.append(record)

    schedule = {
        "schema_version": "rehostrace.schedule/v1",
        "schedule_id": document["schedule_id"],
        "disclosure": document["disclosure"],
        "timeout_ms": document["timeout_ms"],
        "signals": copy.deepcopy(document["signal_order"]),
        "counters": [
            {
                "id": record["id"],
                "threshold": record["threshold"],
                "emit_at_threshold": record["emit_at_threshold"],
            }
            for record in document["counters"]
        ],
        "identity": copy.deepcopy(document["identity"]),
        "points": point_records,
        "claim_boundary": document["claim_boundary"],
    }
    schedule_validation = validate_schedule(schedule)
    report = {
        **validation,
        "schedule_id": schedule["schedule_id"],
        "schedule_sha256": schedule_validation["schedule_sha256"],
    }
    return schedule, report

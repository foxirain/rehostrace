"""Validation and deterministic compilation of lifetime schedules."""

from __future__ import annotations

import copy
import hashlib
import json
import re

from .model import ID_RE


SYMBOL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.$]*")
SELECTOR_KINDS = {"symbol", "module-offset", "tracepoint"}
CAPTURES = {"arg0", "arg1", "arg2", "arg3", "return"}


def _digest(document: dict) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def validate_schedule(schedule: dict) -> dict:
    if not isinstance(schedule, dict) or schedule.get("schema_version") != "rehostrace.schedule/v1":
        raise ValueError("invalid schedule schema_version")
    schedule_id = schedule.get("schedule_id")
    if not isinstance(schedule_id, str) or not ID_RE.fullmatch(schedule_id):
        raise ValueError("invalid schedule_id")
    if schedule.get("disclosure") not in {
        "public-synthetic",
        "private-product",
        "vendor-approved",
    }:
        raise ValueError("invalid schedule disclosure")
    timeout = schedule.get("timeout_ms")
    if type(timeout) is not int or not 1 <= timeout <= 600000:
        raise ValueError("timeout_ms must be in [1, 600000]")
    signal_list = schedule.get("signals")
    if not isinstance(signal_list, list) or not 1 <= len(signal_list) <= 31:
        raise ValueError("signals must contain between 1 and 31 ids")
    if len(signal_list) != len(set(signal_list)) or any(
        not isinstance(item, str) or not ID_RE.fullmatch(item) for item in signal_list
    ):
        raise ValueError("signals must be unique canonical ids")
    signals = set(signal_list)

    counter_records = schedule.get("counters", [])
    counters: dict[str, dict] = {}
    for counter in counter_records:
        counter_id = counter.get("id") if isinstance(counter, dict) else None
        if not isinstance(counter_id, str) or not ID_RE.fullmatch(counter_id):
            raise ValueError("invalid counter id")
        if counter_id in counters:
            raise ValueError(f"duplicate counter: {counter_id}")
        if type(counter.get("threshold")) is not int or counter["threshold"] < 1:
            raise ValueError(f"invalid counter threshold: {counter_id}")
        if counter.get("emit_at_threshold") not in signals:
            raise ValueError(f"counter {counter_id} emits an unknown signal")
        counters[counter_id] = counter

    identity = schedule.get("identity", {"capture": "arg0", "policy": "none"})
    if identity.get("capture") not in CAPTURES or identity.get("policy") not in {
        "same-across-points",
        "per-point",
        "none",
    }:
        raise ValueError("invalid identity policy")

    points: dict[str, dict] = {}
    producers: dict[str, list[str]] = {signal: [] for signal in signals}
    for point in schedule.get("points", []):
        point_id = point.get("id") if isinstance(point, dict) else None
        if not isinstance(point_id, str) or not ID_RE.fullmatch(point_id):
            raise ValueError("invalid schedule point id")
        if point_id in points:
            raise ValueError(f"duplicate schedule point: {point_id}")
        selector = point.get("selector")
        if not isinstance(selector, dict) or selector.get("kind") not in SELECTOR_KINDS:
            raise ValueError(f"invalid selector: {point_id}")
        if selector["kind"] in {"symbol", "tracepoint"}:
            symbol = selector.get("symbol")
            if not isinstance(symbol, str) or not SYMBOL_RE.fullmatch(symbol):
                raise ValueError(f"invalid selector symbol: {point_id}")
        if selector["kind"] == "module-offset":
            expected_hash = selector.get("expected_bytes_sha256")
            if (
                not isinstance(selector.get("module"), str)
                or not SYMBOL_RE.fullmatch(selector["module"])
                or type(selector.get("offset")) is not int
                or selector["offset"] < 0
                or not isinstance(expected_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
            ):
                raise ValueError(f"module-offset selector is incomplete: {point_id}")
        for field in ("emit_on_enter", "wait_for", "emit_on_release"):
            values = point.get(field)
            if not isinstance(values, list) or len(values) != len(set(values)):
                raise ValueError(f"{point_id}.{field} must be a unique list")
            unknown = set(values) - signals
            if unknown:
                raise ValueError(f"{point_id}.{field} has unknown signals: {sorted(unknown)}")
        if "counter" in point and point["counter"] not in counters:
            raise ValueError(f"{point_id} references an unknown counter")
        for signal in point["emit_on_enter"] + point["emit_on_release"]:
            producers[signal].append(point_id)
        points[point_id] = point
    if not points:
        raise ValueError("schedule must contain at least one point")
    for counter in counters.values():
        producers[counter["emit_at_threshold"]].append(f"counter:{counter['id']}")
    waited = {signal for point in points.values() for signal in point["wait_for"]}
    missing = sorted(signal for signal in waited if not producers[signal])
    if missing:
        raise ValueError(f"waited signals have no producer: {missing}")

    return {
        "status": "passed",
        "schedule_id": schedule_id,
        "schedule_sha256": _digest(schedule),
        "signal_count": len(signals),
        "point_count": len(points),
        "counter_count": len(counters),
        "waited_signals": sorted(waited),
    }


def compile_schedule(schedule: dict) -> dict:
    validation = validate_schedule(schedule)
    signal_bits = {signal: index for index, signal in enumerate(schedule["signals"])}

    def mask(names: list[str]) -> int:
        value = 0
        for name in names:
            value |= 1 << signal_bits[name]
        return value

    counters = {record["id"]: index for index, record in enumerate(schedule.get("counters", []))}
    points = []
    for point in schedule["points"]:
        points.append(
            {
                "id": point["id"],
                "selector": copy.deepcopy(point["selector"]),
                "enter_mask": mask(point["emit_on_enter"]),
                "wait_mask": mask(point["wait_for"]),
                "release_mask": mask(point["emit_on_release"]),
                "counter_index": counters.get(point.get("counter"), -1),
            }
        )
    counter_plan = []
    for record in schedule.get("counters", []):
        counter_plan.append(
            {
                "id": record["id"],
                "threshold": record["threshold"],
                "threshold_mask": mask([record["emit_at_threshold"]]),
            }
        )
    return {
        "schema_version": "rehostrace.schedule-plan/v1",
        "schedule_id": schedule["schedule_id"],
        "source_sha256": validation["schedule_sha256"],
        "timeout_ms": schedule["timeout_ms"],
        "signal_bits": signal_bits,
        "identity": copy.deepcopy(schedule.get("identity", {"capture": "arg0", "policy": "none"})),
        "counters": counter_plan,
        "points": points,
        "claim_boundary": schedule.get("claim_boundary", ""),
    }


def _c_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_c_header(schedule: dict) -> str:
    """Render a data-only header consumed by the generic kprobe controller."""

    plan = compile_schedule(schedule)
    unsupported = [
        point["id"]
        for point in plan["points"]
        if point["selector"].get("kind") != "symbol"
    ]
    if unsupported:
        raise ValueError(
            "the kprobe controller currently supports symbol selectors only: "
            + ", ".join(unsupported)
        )
    capture = plan["identity"]["capture"]
    if capture == "return":
        raise ValueError("the kprobe controller does not yet support return-value identity capture")
    capture_index = int(capture[-1])
    same_identity = int(plan["identity"]["policy"] == "same-across-points")
    lines = [
        "/* Generated by RehostRace. Do not edit. */",
        "#ifndef REHOSTRACE_SCHEDULE_GENERATED_H",
        "#define REHOSTRACE_SCHEDULE_GENERATED_H",
        f"#define REHOSTRACE_SCHEDULE_ID {_c_string(plan['schedule_id'])}",
        f"#define REHOSTRACE_SCHEDULE_SOURCE_SHA256 {_c_string(plan['source_sha256'])}",
        f"#define REHOSTRACE_SCHEDULE_TIMEOUT_MS {plan['timeout_ms']}U",
        f"#define REHOSTRACE_SCHEDULE_POINT_COUNT {len(plan['points'])}U",
        f"#define REHOSTRACE_SCHEDULE_COUNTER_COUNT {len(plan['counters'])}U",
        f"#define REHOSTRACE_SCHEDULE_IDENTITY_ARGUMENT {capture_index}U",
        f"#define REHOSTRACE_SCHEDULE_IDENTITY_SAME {same_identity}U",
        "static const struct rehostrace_schedule_point_config rehostrace_schedule_points[] = {",
    ]
    for point in plan["points"]:
        lines.append(
            "\t{ %s, %s, 0x%08xU, 0x%08xU, 0x%08xU, %d },"
            % (
                _c_string(point["id"]),
                _c_string(point["selector"]["symbol"]),
                point["enter_mask"],
                point["wait_mask"],
                point["release_mask"],
                point["counter_index"],
            )
        )
    lines.extend(["};", "static const struct rehostrace_schedule_counter_config rehostrace_schedule_counters[] = {"])
    for counter in plan["counters"]:
        lines.append(
            "\t{ %s, %dU, 0x%08xU },"
            % (_c_string(counter["id"]), counter["threshold"], counter["threshold_mask"])
        )
    lines.extend(["};", "#endif", ""])
    return "\n".join(lines)

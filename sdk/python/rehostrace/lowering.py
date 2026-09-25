"""Hash-bound lowering from lifetime candidates to concrete controller plans."""

from __future__ import annotations

import copy
import hashlib
import json
import re

from .model import ID_RE, SHA256_RE
from .schedule import compile_schedule


SYMBOL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.$]*")
SELECTOR_KINDS = {"symbol", "symbol-offset"}
CAPTURE_KINDS = {"argument", "register"}
PREDICATE_KINDS = {"arg-eq", "arg-ge", "memory-u8-eq", "memory-u16le-eq"}


def _digest(document: dict, *, omit: str | None = None) -> str:
    material = copy.deepcopy(document)
    if omit is not None:
        material.pop(omit, None)
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(f"{label} must be a canonical identifier")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value


def _selector(document: object, label: str, architecture: str) -> dict:
    if not isinstance(document, dict) or document.get("kind") not in SELECTOR_KINDS:
        raise ValueError(f"{label} has an unsupported selector")
    symbol = document.get("symbol")
    if not isinstance(symbol, str) or not SYMBOL_RE.fullmatch(symbol):
        raise ValueError(f"{label}.symbol is invalid")
    normalized = {"kind": document["kind"], "symbol": symbol, "offset": 0}
    if document["kind"] == "symbol-offset":
        offset = document.get("offset")
        if type(offset) is not int or offset < 0:
            raise ValueError(f"{label}.offset must be a non-negative integer")
        if architecture == "aarch64" and offset % 4:
            raise ValueError(f"{label}.offset must be instruction aligned for aarch64")
        normalized["offset"] = offset
        normalized["expected_bytes_sha256"] = _sha256(
            document.get("expected_bytes_sha256"),
            f"{label}.expected_bytes_sha256",
        )
    elif "offset" in document or "expected_bytes_sha256" in document:
        raise ValueError(f"{label} symbol selector cannot carry offset evidence")
    return normalized


def _capture(document: object, label: str, architecture: str) -> dict:
    if not isinstance(document, dict) or document.get("kind") not in CAPTURE_KINDS:
        raise ValueError(f"{label} has an unsupported identity capture")
    index = document.get("index")
    if type(index) is not int or index < 0:
        raise ValueError(f"{label}.index must be a non-negative integer")
    if document["kind"] == "argument" and index > 7:
        raise ValueError(f"{label} argument index exceeds the supported ABI range")
    if document["kind"] == "register":
        if architecture != "aarch64":
            raise ValueError(f"{label} register capture currently requires aarch64")
        if index > 30:
            raise ValueError(f"{label} register index exceeds the aarch64 GPR range")
    return {"kind": document["kind"], "index": index}


def _predicate(document: object, label: str) -> dict:
    if not isinstance(document, dict) or document.get("kind") not in PREDICATE_KINDS:
        raise ValueError(f"{label} has an unsupported predicate")
    kind = document["kind"]
    normalized = {"kind": kind}
    if kind in {"arg-eq", "arg-ge"}:
        index = document.get("argument")
        value = document.get("value")
        if type(index) is not int or not 0 <= index <= 7 or type(value) is not int or value < 0:
            raise ValueError(f"{label} has invalid argument predicate fields")
        normalized.update({"argument": index, "offset": 0, "value": value})
    else:
        index = document.get("base_argument")
        offset = document.get("offset")
        value = document.get("value")
        maximum = 0xFF if kind == "memory-u8-eq" else 0xFFFF
        if (
            type(index) is not int
            or not 0 <= index <= 7
            or type(offset) is not int
            or offset < 0
            or type(value) is not int
            or not 0 <= value <= maximum
        ):
            raise ValueError(f"{label} has invalid memory predicate fields")
        normalized.update({"argument": index, "offset": offset, "value": value})
    return normalized


def _validate_analysis(analysis: dict, schedules: dict) -> None:
    if analysis.get("schema_version") != "rehostrace.lifetime-candidates/v1":
        raise ValueError("unsupported lifetime analysis schema")
    if analysis.get("report_sha256") != _digest(analysis, omit="report_sha256"):
        raise ValueError("lifetime analysis integrity hash mismatch")
    if schedules.get("schema_version") != "rehostrace.schedule-candidates/v1":
        raise ValueError("unsupported schedule candidate schema")
    if schedules.get("analysis_sha256") != analysis["report_sha256"]:
        raise ValueError("schedule candidates do not bind the lifetime analysis")
    if schedules.get("report_sha256") != _digest(schedules, omit="report_sha256"):
        raise ValueError("schedule candidate integrity hash mismatch")


def validate_target_lowering(
    analysis: dict,
    schedules: dict,
    schedule: dict,
    lowering: dict,
) -> dict:
    """Validate a declarative mapping without generating executable code."""

    _validate_analysis(analysis, schedules)
    if lowering.get("schema_version") != "rehostrace.target-lowering/v1":
        raise ValueError("unsupported target lowering schema")
    lowering_id = _id(lowering.get("lowering_id"), "lowering_id")
    source = lowering.get("source")
    if not isinstance(source, dict):
        raise ValueError("target lowering source binding is required")
    if source.get("analysis_sha256") != analysis["report_sha256"]:
        raise ValueError("target lowering analysis_sha256 drifted")
    if source.get("schedule_candidates_sha256") != schedules["report_sha256"]:
        raise ValueError("target lowering schedule_candidates_sha256 drifted")

    candidates = {item.get("candidate_id"): item for item in analysis.get("candidates", [])}
    candidate_id = source.get("candidate_id")
    candidate = candidates.get(candidate_id)
    if candidate is None:
        raise ValueError("target lowering references an unknown lifetime candidate")
    schedule_candidates = {
        item.get("schedule_id"): item for item in schedules.get("schedules", [])
    }
    candidate_schedule_id = source.get("schedule_candidate_id")
    candidate_schedule = schedule_candidates.get(candidate_schedule_id)
    if candidate_schedule is None or candidate_schedule.get("candidate_id") != candidate_id:
        raise ValueError("target lowering references an unrelated schedule candidate")

    schedule_plan = compile_schedule(schedule)
    if source.get("detailed_schedule_sha256") != schedule_plan["source_sha256"]:
        raise ValueError("target lowering detailed schedule hash drifted")
    target = lowering.get("target")
    if not isinstance(target, dict):
        raise ValueError("target lowering target is required")
    target_id = _id(target.get("id"), "target.id")
    architecture = target.get("architecture")
    if architecture not in {"aarch64", "x86_64", "um"}:
        raise ValueError("unsupported target architecture")
    binary_sha256 = _sha256(target.get("binary_sha256"), "target.binary_sha256")
    if binary_sha256 != analysis.get("binary_sha256"):
        raise ValueError("target binary identity differs from the analyzed CFG")
    module = target.get("module")
    if not isinstance(module, str) or not SYMBOL_RE.fullmatch(module):
        raise ValueError("target.module is invalid")
    if target.get("backend") != "linux-kprobe":
        raise ValueError("only the linux-kprobe backend is currently supported")

    candidate_paths = {item["node"] for item in candidate.get("paths", [])}
    roles: dict[str, dict] = {}
    for index, record in enumerate(lowering.get("roles", [])):
        if not isinstance(record, dict):
            raise ValueError("role records must be objects")
        role_id = _id(record.get("id"), f"roles[{index}].id")
        if role_id in roles:
            raise ValueError(f"duplicate role: {role_id}")
        path = record.get("path")
        if path not in candidate_paths:
            raise ValueError(f"role {role_id} does not map a candidate path")
        predicates = [
            _predicate(item, f"roles[{index}].predicates[{position}]")
            for position, item in enumerate(record.get("predicates", []))
        ]
        roles[role_id] = {
            "id": role_id,
            "path": path,
            "selector": _selector(record.get("classifier"), f"roles[{index}].classifier", architecture),
            "predicates": predicates,
        }
    if not roles or {record["path"] for record in roles.values()} != candidate_paths:
        raise ValueError("roles must cover every candidate path exactly by meaning")

    schedule_points = {item["id"]: item for item in schedule_plan["points"]}
    point_bindings: dict[str, dict] = {}
    for index, record in enumerate(lowering.get("point_bindings", [])):
        if not isinstance(record, dict):
            raise ValueError("point binding records must be objects")
        point_id = record.get("point_id")
        if point_id not in schedule_points or point_id in point_bindings:
            raise ValueError(f"unknown or duplicate point binding: {point_id}")
        role = record.get("role")
        if role != "any" and role not in roles:
            raise ValueError(f"point {point_id} references an unknown role")
        point_bindings[point_id] = {
            "point_id": point_id,
            "role": role,
            "selector": _selector(record.get("selector"), f"point_bindings[{index}].selector", architecture),
            "identity_capture": _capture(
                record.get("identity_capture"),
                f"point_bindings[{index}].identity_capture",
                architecture,
            ),
        }
    if set(point_bindings) != set(schedule_points):
        missing = sorted(set(schedule_points) - set(point_bindings))
        extra = sorted(set(point_bindings) - set(schedule_points))
        raise ValueError(f"point bindings must exactly cover the detailed schedule: missing={missing} extra={extra}")

    observers: dict[str, dict] = {}
    for index, record in enumerate(lowering.get("observers", [])):
        if not isinstance(record, dict):
            raise ValueError("observer records must be objects")
        observer_id = _id(record.get("id"), f"observers[{index}].id")
        if observer_id in observers:
            raise ValueError(f"duplicate observer: {observer_id}")
        role = record.get("role")
        if role != "any" and role not in roles:
            raise ValueError(f"observer {observer_id} references an unknown role")
        capture = record.get("identity_capture")
        observers[observer_id] = {
            "id": observer_id,
            "role": role,
            "selector": _selector(record.get("selector"), f"observers[{index}].selector", architecture),
            "identity_capture": (
                None
                if capture is None
                else _capture(capture, f"observers[{index}].identity_capture", architecture)
            ),
        }

    relations = []
    for index, record in enumerate(lowering.get("symbol_relations", [])):
        if not isinstance(record, dict):
            raise ValueError("symbol relation records must be objects")
        left = record.get("left")
        right = record.get("right")
        delta = record.get("delta")
        if (
            not isinstance(left, str)
            or not SYMBOL_RE.fullmatch(left)
            or not isinstance(right, str)
            or not SYMBOL_RE.fullmatch(right)
            or type(delta) is not int
        ):
            raise ValueError(f"symbol_relations[{index}] is invalid")
        relations.append({"left": left, "right": right, "delta": delta})

    if candidate_schedule.get("oracle", {}).get("require_same_identity") is True:
        if schedule_plan.get("identity", {}).get("policy") != "same-across-points":
            raise ValueError("same-identity candidate requires a same-across-points detailed schedule")
    claim_boundary = lowering.get("claim_boundary")
    if not isinstance(claim_boundary, str) or not claim_boundary:
        raise ValueError("target lowering claim_boundary must be non-empty")

    normalized = {
        "lowering_id": lowering_id,
        "source": {
            "analysis_sha256": analysis["report_sha256"],
            "schedule_candidates_sha256": schedules["report_sha256"],
            "candidate_id": candidate_id,
            "schedule_candidate_id": candidate_schedule_id,
            "detailed_schedule_sha256": schedule_plan["source_sha256"],
        },
        "target": {
            "id": target_id,
            "binary_sha256": binary_sha256,
            "architecture": architecture,
            "module": module,
            "backend": target["backend"],
        },
        "roles": [roles[key] for key in sorted(roles)],
        "point_bindings": [point_bindings[key] for key in sorted(point_bindings)],
        "observers": [observers[key] for key in sorted(observers)],
        "symbol_relations": sorted(relations, key=lambda item: (item["left"], item["right"], item["delta"])),
        "claim_boundary": claim_boundary,
    }
    return {
        "status": "passed",
        "lowering_id": lowering_id,
        "target_id": target_id,
        "candidate_id": candidate_id,
        "point_count": len(point_bindings),
        "role_count": len(roles),
        "observer_count": len(observers),
        "normalized": normalized,
        "lowering_sha256": _digest(normalized),
    }


def compile_target_controller(
    analysis: dict,
    schedules: dict,
    schedule: dict,
    lowering: dict,
) -> dict:
    """Lower a validated candidate and detailed schedule into a backend plan."""

    validation = validate_target_lowering(analysis, schedules, schedule, lowering)
    normalized = validation["normalized"]
    schedule_plan = compile_schedule(schedule)
    roles = normalized["roles"]
    role_indexes = {record["id"]: index for index, record in enumerate(roles)}
    bindings = {record["point_id"]: record for record in normalized["point_bindings"]}
    points = []
    for point in schedule_plan["points"]:
        binding = bindings[point["id"]]
        points.append(
            {
                "id": point["id"],
                "selector": binding["selector"],
                "role": binding["role"],
                "role_index": -1 if binding["role"] == "any" else role_indexes[binding["role"]],
                "identity_capture": binding["identity_capture"],
                "enter_mask": point["enter_mask"],
                "wait_mask": point["wait_mask"],
                "release_mask": point["release_mask"],
                "counter_index": point["counter_index"],
            }
        )
    plan = {
        "schema_version": "rehostrace.controller-plan/v1",
        "lowering_id": normalized["lowering_id"],
        "lowering_sha256": validation["lowering_sha256"],
        "source": copy.deepcopy(normalized["source"]),
        "target": copy.deepcopy(normalized["target"]),
        "identity": copy.deepcopy(schedule_plan["identity"]),
        "timeout_ms": schedule_plan["timeout_ms"],
        "signals": copy.deepcopy(schedule_plan["signal_bits"]),
        "counters": copy.deepcopy(schedule_plan["counters"]),
        "roles": copy.deepcopy(roles),
        "points": points,
        "observers": copy.deepcopy(normalized["observers"]),
        "symbol_relations": copy.deepcopy(normalized["symbol_relations"]),
        "claim_boundary": normalized["claim_boundary"],
    }
    plan["plan_sha256"] = _digest(plan)
    return plan


def _c_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _capture_numbers(capture: dict | None) -> tuple[int, int]:
    if capture is None:
        return 0, 0
    return (1 if capture["kind"] == "argument" else 2), capture["index"]


def render_target_controller_header(plan: dict) -> str:
    """Render a data-only header for a generic kprobe lowering backend."""

    if plan.get("schema_version") != "rehostrace.controller-plan/v1":
        raise ValueError("unsupported controller plan schema")
    if plan.get("plan_sha256") != _digest(plan, omit="plan_sha256"):
        raise ValueError("controller plan integrity hash mismatch")
    lines = [
        "/* Generated by RehostRace target lowering. Do not edit. */",
        "#ifndef REHOSTRACE_TARGET_LOWERED_GENERATED_H",
        "#define REHOSTRACE_TARGET_LOWERED_GENERATED_H",
        "#define REHOSTRACE_CAPTURE_NONE 0U",
        "#define REHOSTRACE_CAPTURE_ARGUMENT 1U",
        "#define REHOSTRACE_CAPTURE_REGISTER 2U",
        f"#define REHOSTRACE_LOWERING_ID {_c_string(plan['lowering_id'])}",
        f"#define REHOSTRACE_LOWERING_SHA256 {_c_string(plan['lowering_sha256'])}",
        f"#define REHOSTRACE_CONTROLLER_PLAN_SHA256 {_c_string(plan['plan_sha256'])}",
        f"#define REHOSTRACE_TARGET_ID {_c_string(plan['target']['id'])}",
        f"#define REHOSTRACE_TARGET_MODULE {_c_string(plan['target']['module'])}",
        f"#define REHOSTRACE_TARGET_ARCHITECTURE {_c_string(plan['target']['architecture'])}",
        f"#define REHOSTRACE_TARGET_BINARY_SHA256 {_c_string(plan['target']['binary_sha256'])}",
        f"#define REHOSTRACE_TARGET_TIMEOUT_MS {plan['timeout_ms']}U",
        "#define REHOSTRACE_TARGET_IDENTITY_SAME %dU"
        % (plan["identity"]["policy"] == "same-across-points"),
        f"#define REHOSTRACE_TARGET_ROLE_COUNT {len(plan['roles'])}U",
        f"#define REHOSTRACE_TARGET_POINT_COUNT {len(plan['points'])}U",
        f"#define REHOSTRACE_TARGET_OBSERVER_COUNT {len(plan['observers'])}U",
        f"#define REHOSTRACE_TARGET_COUNTER_COUNT {len(plan['counters'])}U",
        "static const struct rehostrace_lowered_role_config rehostrace_lowered_roles[] = {",
    ]
    predicate_offset = 0
    predicates = []
    predicate_kind = {"arg-eq": 1, "arg-ge": 2, "memory-u8-eq": 3, "memory-u16le-eq": 4}
    for role in plan["roles"]:
        lines.append(
            "\t{ %s, %s, 0x%xUL, %dU, %dU },"
            % (
                _c_string(role["id"]),
                _c_string(role["selector"]["symbol"]),
                role["selector"]["offset"],
                predicate_offset,
                len(role["predicates"]),
            )
        )
        for item in role["predicates"]:
            predicates.append(
                (predicate_kind[item["kind"]], item["argument"], item["offset"], item["value"])
            )
        predicate_offset += len(role["predicates"])
    lines.extend(["};", "static const struct rehostrace_lowered_predicate_config rehostrace_lowered_predicates[] = {"])
    for kind, argument, offset, value in predicates:
        lines.append(f"\t{{ {kind}U, {argument}U, {offset}U, 0x{value:x}UL }},")
    lines.extend(["};", "static const struct rehostrace_lowered_counter_config rehostrace_lowered_counters[] = {"])
    for counter in plan["counters"]:
        lines.append(
            "\t{ %s, %dU, 0x%08xU },"
            % (_c_string(counter["id"]), counter["threshold"], counter["threshold_mask"])
        )
    lines.extend(["};", "static const struct rehostrace_lowered_point_config rehostrace_lowered_points[] = {"])
    for point in plan["points"]:
        capture_kind, capture_index = _capture_numbers(point["identity_capture"])
        lines.append(
            "\t{ %s, %s, 0x%xUL, %d, %dU, %dU, 0x%08xU, 0x%08xU, 0x%08xU, %d },"
            % (
                _c_string(point["id"]),
                _c_string(point["selector"]["symbol"]),
                point["selector"]["offset"],
                point["role_index"],
                capture_kind,
                capture_index,
                point["enter_mask"],
                point["wait_mask"],
                point["release_mask"],
                point["counter_index"],
            )
        )
    lines.extend(["};", "static const struct rehostrace_lowered_observer_config rehostrace_lowered_observers[] = {"])
    role_indexes = {role["id"]: index for index, role in enumerate(plan["roles"])}
    for observer in plan["observers"]:
        capture_kind, capture_index = _capture_numbers(observer["identity_capture"])
        role_index = -1 if observer["role"] == "any" else role_indexes[observer["role"]]
        lines.append(
            "\t{ %s, %s, 0x%xUL, %d, %dU, %dU },"
            % (
                _c_string(observer["id"]),
                _c_string(observer["selector"]["symbol"]),
                observer["selector"]["offset"],
                role_index,
                capture_kind,
                capture_index,
            )
        )
    lines.extend(["};", "static const struct rehostrace_lowered_relation_config rehostrace_lowered_relations[] = {"])
    for relation in plan["symbol_relations"]:
        lines.append(
            "\t{ %s, %s, %dL },"
            % (_c_string(relation["left"]), _c_string(relation["right"]), relation["delta"])
        )
    lines.extend(
        [
            "};",
            f"#define REHOSTRACE_TARGET_PREDICATE_COUNT {len(predicates)}U",
            f"#define REHOSTRACE_TARGET_RELATION_COUNT {len(plan['symbol_relations'])}U",
            "#endif",
            "",
        ]
    )
    return "\n".join(lines)

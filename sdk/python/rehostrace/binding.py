"""Hash-bound projection of causal events onto concrete adapter actions."""

from __future__ import annotations

import copy
import hashlib
import json
import re

from .model import CausalTrace, ID_RE, SHA256_RE
from .schedule import compile_schedule


def _digest(document: dict) -> str:
    normalized = copy.deepcopy(document)
    if isinstance(normalized.get("actions"), list):
        normalized["actions"] = sorted(normalized["actions"], key=lambda item: item["id"])
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _decode_payload(payload: dict, action_id: str) -> bytes:
    if not isinstance(payload, dict):
        raise ValueError(f"action {action_id} payload must be an object")
    encoding = payload.get("encoding")
    data = payload.get("data")
    if encoding not in {"hex", "utf8"} or not isinstance(data, str):
        raise ValueError(f"action {action_id} payload encoding is invalid")
    try:
        decoded = bytes.fromhex(data) if encoding == "hex" else data.encode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise ValueError(f"action {action_id} payload cannot be decoded") from error
    if type(payload.get("length")) is not int or payload["length"] != len(decoded) or not decoded:
        raise ValueError(f"action {action_id} payload length mismatch")
    digest = payload.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ValueError(f"action {action_id} payload digest is invalid")
    if hashlib.sha256(decoded).hexdigest() != digest:
        raise ValueError(f"action {action_id} payload digest mismatch")
    return decoded


def validate_binding(binding: dict, trace: CausalTrace, schedule: dict) -> dict:
    if not isinstance(binding, dict) or binding.get("schema_version") != "rehostrace.binding/v1":
        raise ValueError("invalid binding schema_version")
    binding_id = binding.get("binding_id")
    if not isinstance(binding_id, str) or not ID_RE.fullmatch(binding_id):
        raise ValueError("invalid binding_id")
    if binding.get("trace_sha256") != trace.digest:
        raise ValueError("binding trace_sha256 does not match the causal trace")
    schedule_plan = compile_schedule(schedule)
    if binding.get("schedule_sha256") != schedule_plan["source_sha256"]:
        raise ValueError("binding schedule_sha256 does not match the lifetime schedule")
    adapter = binding.get("adapter")
    if not isinstance(adapter, str) or not ID_RE.fullmatch(adapter):
        raise ValueError("invalid adapter id")
    if not isinstance(binding.get("claim_boundary"), str) or not binding["claim_boundary"]:
        raise ValueError("binding claim_boundary must be non-empty")
    action_list = binding.get("actions")
    if not isinstance(action_list, list) or not action_list:
        raise ValueError("binding must contain at least one action")

    actions: dict[str, dict] = {}
    event_ids: set[str] = set()
    groups: dict[str, list[str]] = {}
    for record in action_list:
        action_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(action_id, str) or not ID_RE.fullmatch(action_id) or action_id in actions:
            raise ValueError("binding action ids must be unique canonical ids")
        event_id = record.get("event_id")
        if event_id not in trace.events or event_id in event_ids:
            raise ValueError(f"action {action_id} references an unknown or duplicate event")
        endpoint = record.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.startswith("/") or "\x00" in endpoint:
            raise ValueError(f"action {action_id} endpoint must be an absolute guest path")
        launch_group = record.get("launch_group")
        if not isinstance(launch_group, str) or not ID_RE.fullmatch(launch_group):
            raise ValueError(f"action {action_id} has an invalid launch group")
        start_signal = record.get("start_after_signal")
        if start_signal is not None and start_signal not in schedule_plan["signal_bits"]:
            raise ValueError(f"action {action_id} references an unknown schedule signal")
        decoded = _decode_payload(record.get("payload"), action_id)
        actions[action_id] = {**copy.deepcopy(record), "decoded": decoded}
        event_ids.add(event_id)
        groups.setdefault(launch_group, []).append(event_id)

    for group_id, group_events in groups.items():
        for index, first in enumerate(group_events):
            for second in group_events[index + 1 :]:
                if not trace.concurrent(first, second):
                    raise ValueError(
                        f"launch group {group_id} contains causally ordered events: {first}, {second}"
                    )

    return {
        "status": "passed",
        "binding_id": binding_id,
        "binding_sha256": _digest(binding),
        "trace_sha256": trace.digest,
        "schedule_sha256": schedule_plan["source_sha256"],
        "action_count": len(actions),
        "launch_groups": {key: sorted(value) for key, value in sorted(groups.items())},
    }


def compile_binding(binding: dict, trace: CausalTrace, schedule: dict) -> dict:
    validation = validate_binding(binding, trace, schedule)
    schedule_plan = compile_schedule(schedule)
    actions = []
    for record in sorted(binding["actions"], key=lambda item: item["id"]):
        event = trace.events[record["event_id"]]
        decoded = _decode_payload(record["payload"], record["id"])
        actions.append(
            {
                "id": record["id"],
                "event_id": record["event_id"],
                "operation": event["boundary"]["operation"],
                "direction": event["boundary"]["direction"],
                "endpoint": record["endpoint"],
                "launch_group": record["launch_group"],
                "start_after_signal": record.get("start_after_signal"),
                "start_mask": (
                    0
                    if record.get("start_after_signal") is None
                    else 1 << schedule_plan["signal_bits"][record["start_after_signal"]]
                ),
                "payload_hex": decoded.hex(),
                "payload_sha256": record["payload"]["sha256"],
            }
        )
    return {
        "schema_version": "rehostrace.binding-plan/v1",
        "binding_id": binding["binding_id"],
        "binding_sha256": validation["binding_sha256"],
        "trace_id": trace.document["trace_id"],
        "trace_sha256": trace.digest,
        "schedule_sha256": schedule_plan["source_sha256"],
        "adapter": binding["adapter"],
        "actions": actions,
        "claim_boundary": binding["claim_boundary"],
    }


def _macro_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", value).upper()


def _c_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_binding_header(binding: dict, trace: CausalTrace, schedule: dict) -> str:
    """Render fixture-consumable action constants from a validated binding."""

    plan = compile_binding(binding, trace, schedule)
    lines = [
        "/* Generated by RehostRace. Do not edit. */",
        "#ifndef REHOSTRACE_BOUNDARY_BINDING_GENERATED_H",
        "#define REHOSTRACE_BOUNDARY_BINDING_GENERATED_H",
        f"#define REHOSTRACE_BOUNDARY_BINDING_ID {_c_string(plan['binding_id'])}",
        f"#define REHOSTRACE_BOUNDARY_BINDING_SHA256 {_c_string(plan['binding_sha256'])}",
        f"#define REHOSTRACE_BOUNDARY_TRACE_ID {_c_string(plan['trace_id'])}",
        f"#define REHOSTRACE_BOUNDARY_TRACE_SHA256 {_c_string(plan['trace_sha256'])}",
        f"#define REHOSTRACE_BOUNDARY_SCHEDULE_SHA256 {_c_string(plan['schedule_sha256'])}",
        f"#define REHOSTRACE_BOUNDARY_ACTION_COUNT {len(plan['actions'])}U",
    ]
    for action in plan["actions"]:
        macro = _macro_id(action["id"])
        payload = bytes.fromhex(action["payload_hex"])
        if len(payload) != 1:
            raise ValueError(
                f"the public C fixture currently supports one-byte actions only: {action['id']}"
            )
        lines.extend(
            [
                f"#define REHOSTRACE_BOUNDARY_{macro}_EVENT_ID {_c_string(action['event_id'])}",
                f"#define REHOSTRACE_BOUNDARY_{macro}_OPERATION {_c_string(action['operation'])}",
                f"#define REHOSTRACE_BOUNDARY_{macro}_ENDPOINT {_c_string(action['endpoint'])}",
                f"#define REHOSTRACE_BOUNDARY_{macro}_PAYLOAD 0x{payload[0]:02x}U",
                f"#define REHOSTRACE_BOUNDARY_{macro}_START_MASK 0x{action['start_mask']:08x}U",
            ]
        )
    lines.extend(["#endif", ""])
    return "\n".join(lines)

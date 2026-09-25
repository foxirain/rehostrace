"""Data-only execution plans for native-stack and controller harnesses."""

from __future__ import annotations

import copy
import hashlib
import json


KINDS = {"android-native-stack", "controller-firmware"}
TRANSPORTS = {"stdio", "unix-socket", "shared-memory", "qemu-device", "binder-proxy", "hci-user", "remote-hil"}
ACTIONS = {"reset", "load", "feed", "observe", "collect"}


def _digest(document: dict) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_harness_plan(document: dict) -> dict:
    if document.get("schema_version") != "rehostrace.harness-plan/v1":
        raise ValueError("unsupported harness plan schema")
    if document.get("kind") not in KINDS:
        raise ValueError("harness kind is invalid")
    if document.get("transport") not in TRANSPORTS:
        raise ValueError("harness transport is invalid")
    identity = document.get("identity")
    if not isinstance(identity, dict):
        raise ValueError("harness plan requires identity")
    for key in ("target_sha256", "runner_sha256"):
        value = identity.get(key)
        if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError(f"harness identity requires {key}")
    stages = document.get("stages")
    if not isinstance(stages, list) or not stages:
        raise ValueError("harness plan requires stages")
    ids = set()
    for stage in stages:
        if not isinstance(stage, dict) or not isinstance(stage.get("id"), str) or stage["id"] in ids:
            raise ValueError("harness stage ids must be unique")
        ids.add(stage["id"])
        if stage.get("action") not in ACTIONS:
            raise ValueError("harness stage action is invalid")
        if type(stage.get("timeout_ms")) is not int or not 1 <= stage["timeout_ms"] <= 600_000:
            raise ValueError("harness stage timeout is invalid")
    if stages[0]["action"] != "reset" or stages[-1]["action"] != "collect":
        raise ValueError("harness plan must reset first and collect last")
    return copy.deepcopy(document)


def compile_harness_plan(document: dict) -> dict:
    plan = validate_harness_plan(document)
    result = {
        "schema_version": "rehostrace.harness-execution/v1",
        "plan_id": plan["plan_id"],
        "kind": plan["kind"],
        "transport": plan["transport"],
        "plan_sha256": _digest(plan),
        "identity": copy.deepcopy(plan["identity"]),
        "stage_order": [stage["id"] for stage in plan["stages"]],
        "timeouts_ms": {stage["id"]: stage["timeout_ms"] for stage in plan["stages"]},
        "inputs": copy.deepcopy(plan.get("inputs", [])),
        "outputs": copy.deepcopy(plan.get("outputs", [])),
        "executable": False,
        "claim_boundary": "This is a validated, hash-pinned execution contract; a backend runner must execute and attest it separately.",
    }
    result["execution_sha256"] = _digest(result)
    return result

"""Normalized binary-CFG lifetime analysis and schedule candidate synthesis."""

from __future__ import annotations

import copy
import hashlib
import json


def _digest(document: dict) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_binary_cfg(document: dict) -> dict:
    if document.get("schema_version") != "rehostrace.binary-cfg/v1":
        raise ValueError("unsupported binary CFG schema")
    binary = document.get("binary")
    if not isinstance(binary, dict) or not isinstance(binary.get("sha256"), str) or len(binary["sha256"]) != 64:
        raise ValueError("binary CFG requires a SHA-256 identity")
    nodes = document.get("nodes")
    edges = document.get("edges", [])
    if not isinstance(nodes, list) or not nodes or not isinstance(edges, list):
        raise ValueError("binary CFG requires nodes and edges")
    node_ids = [node.get("id") for node in nodes if isinstance(node, dict)]
    if len(node_ids) != len(nodes) or None in node_ids or len(node_ids) != len(set(node_ids)):
        raise ValueError("binary CFG nodes require unique ids")
    known = set(node_ids)
    for node in nodes:
        if type(node.get("async_entry")) is not bool:
            raise ValueError("CFG node async_entry must be boolean")
        operations = node.get("operations", [])
        if not isinstance(operations, list):
            raise ValueError("CFG node operations must be a list")
        held: set[str] = set()
        for operation in operations:
            if not isinstance(operation, dict) or operation.get("kind") not in {"acquire", "release", "alloc", "free", "use", "call"}:
                raise ValueError("CFG operation kind is invalid")
            if operation["kind"] in {"acquire", "release"}:
                lock = operation.get("lock")
                if not isinstance(lock, str) or not lock:
                    raise ValueError("lock operation requires lock")
                if operation["kind"] == "acquire":
                    held.add(lock)
                elif lock not in held:
                    raise ValueError("lock release has no matching local acquire")
                else:
                    held.remove(lock)
            if operation["kind"] in {"alloc", "free", "use"} and not isinstance(operation.get("resource"), str):
                raise ValueError("lifetime operation requires resource")
            if not isinstance(operation.get("site"), str) or not operation["site"]:
                raise ValueError("CFG operation requires site")
        if held:
            raise ValueError("CFG node ends with locally held locks")
    for edge in edges:
        if not isinstance(edge, dict) or edge.get("from") not in known or edge.get("to") not in known:
            raise ValueError("CFG edge references an unknown node")
        if edge.get("kind") not in {"control", "call", "async"}:
            raise ValueError("CFG edge kind is invalid")
    return copy.deepcopy(document)


def _handoffs(node: dict) -> list[dict]:
    operations = node["operations"]
    results = []
    for first, operation in enumerate(operations):
        if operation["kind"] != "release":
            continue
        for second in range(first + 1, len(operations)):
            later = operations[second]
            if later["kind"] == "acquire" and later["lock"] != operation["lock"]:
                results.append(
                    {
                        "released_lock": operation["lock"],
                        "release_site": operation["site"],
                        "acquired_lock": later["lock"],
                        "acquire_site": later["site"],
                    }
                )
                break
    return results


def analyze_lifetime_cfg(document: dict) -> dict:
    cfg = validate_binary_cfg(document)
    nodes = {node["id"]: node for node in cfg["nodes"]}
    free_paths: dict[str, list[dict]] = {}
    use_paths: dict[str, list[dict]] = {}
    handoffs = {node_id: _handoffs(node) for node_id, node in nodes.items()}
    for node_id, node in nodes.items():
        for operation in node["operations"]:
            record = {"node": node_id, "site": operation["site"], "async_entry": node["async_entry"]}
            if operation["kind"] == "free":
                free_paths.setdefault(operation["resource"], []).append(record)
            elif operation["kind"] == "use":
                use_paths.setdefault(operation["resource"], []).append(record)

    candidates = []
    for resource, frees in sorted(free_paths.items()):
        for left_index, left in enumerate(frees):
            for right in frees[left_index + 1 :]:
                if left["node"] == right["node"] or not (left["async_entry"] and right["async_entry"]):
                    continue
                candidates.append(
                    {
                        "candidate_id": f"double-free:{resource}:{left['node']}:{right['node']}",
                        "kind": "same-resource-multi-free",
                        "resource": resource,
                        "paths": [left, right],
                        "handoffs": sorted(
                            handoffs[left["node"]] + handoffs[right["node"]],
                            key=lambda item: (item["release_site"], item["acquire_site"]),
                        ),
                        "confidence": "structural-candidate",
                    }
                )
        if frees and resource in use_paths:
            for free in frees:
                for use in use_paths[resource]:
                    if free["node"] != use["node"] and free["async_entry"] and use["async_entry"]:
                        candidates.append(
                            {
                                "candidate_id": f"uaf:{resource}:{free['node']}:{use['node']}",
                                "kind": "free-use-overlap",
                                "resource": resource,
                                "paths": [free, use],
                                "handoffs": copy.deepcopy(handoffs[free["node"]] + handoffs[use["node"]]),
                                "confidence": "structural-candidate",
                            }
                        )
    report = {
        "schema_version": "rehostrace.lifetime-candidates/v1",
        "binary_sha256": cfg["binary"]["sha256"],
        "cfg_sha256": _digest(cfg),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "claim_boundary": "Structural candidates require replay and a runtime identity oracle before they become confirmed lifetime defects.",
    }
    report["report_sha256"] = _digest(report)
    return report


def synthesize_lifetime_schedules(analysis: dict) -> dict:
    if analysis.get("schema_version") != "rehostrace.lifetime-candidates/v1":
        raise ValueError("unsupported lifetime candidate analysis")
    schedules = []
    for candidate in analysis.get("candidates", []):
        paths = candidate.get("paths", [])
        if len(paths) != 2:
            continue
        first, second = paths
        gates = [
            {"id": "a.enter", "path": first["node"], "site": first["site"]},
            {"id": "b.enter", "path": second["node"], "site": second["site"]},
            {"id": "b.sink", "path": second["node"], "site": second["site"]},
            {"id": "a.sink", "path": first["node"], "site": first["site"]},
        ]
        precedence = [["a.enter", "b.enter"], ["b.enter", "b.sink"], ["b.sink", "a.sink"]]
        schedules.append(
            {
                "schedule_id": f"schedule:{candidate['candidate_id']}",
                "candidate_id": candidate["candidate_id"],
                "gates": gates,
                "precedence": precedence,
                "oracle": {"resource": candidate["resource"], "require_same_identity": True, "sink_count": 2 if candidate["kind"] == "same-resource-multi-free" else 1},
            }
        )
    result = {
        "schema_version": "rehostrace.schedule-candidates/v1",
        "analysis_sha256": analysis["report_sha256"],
        "schedules": schedules,
    }
    result["report_sha256"] = _digest(result)
    return result

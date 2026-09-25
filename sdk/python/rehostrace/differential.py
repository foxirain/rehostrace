"""Hash-pinned semantic differential analysis across target versions."""

from __future__ import annotations

import copy
import hashlib
import json


def _digest(document: dict) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_target_manifest(document: dict) -> dict:
    if document.get("schema_version") != "rehostrace.target-manifest/v1":
        raise ValueError("unsupported target manifest schema")
    for key in ("target_family", "version"):
        if not isinstance(document.get(key), str) or not document[key]:
            raise ValueError(f"target manifest requires {key}")
    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("target manifest requires components")
    ids = set()
    for component in components:
        if not isinstance(component, dict) or not isinstance(component.get("id"), str) or component["id"] in ids:
            raise ValueError("component ids must be unique")
        ids.add(component["id"])
        if component.get("kind") not in {"kernel-module", "native-library", "service", "controller-image", "fixture"}:
            raise ValueError("component kind is invalid")
        digest = component.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("component requires lowercase SHA-256")
        facts = component.get("facts", {})
        if not isinstance(facts, dict) or any(not isinstance(value, list) for value in facts.values()):
            raise ValueError("component facts must map names to lists")
    return copy.deepcopy(document)


def compare_target_manifests(baseline_document: dict, candidate_document: dict) -> dict:
    baseline = validate_target_manifest(baseline_document)
    candidate = validate_target_manifest(candidate_document)
    if baseline["target_family"] != candidate["target_family"]:
        raise ValueError("target manifests belong to different families")
    old = {item["id"]: item for item in baseline["components"]}
    new = {item["id"]: item for item in candidate["components"]}
    changes = []
    for component_id in sorted(old.keys() | new.keys()):
        if component_id not in old:
            changes.append({"component_id": component_id, "change": "added"})
            continue
        if component_id not in new:
            changes.append({"component_id": component_id, "change": "removed"})
            continue
        before, after = old[component_id], new[component_id]
        fact_changes = {}
        for fact_name in sorted(set(before.get("facts", {})) | set(after.get("facts", {}))):
            left = {json.dumps(item, sort_keys=True) for item in before.get("facts", {}).get(fact_name, [])}
            right = {json.dumps(item, sort_keys=True) for item in after.get("facts", {}).get(fact_name, [])}
            if left != right:
                fact_changes[fact_name] = {
                    "added": [json.loads(item) for item in sorted(right - left)],
                    "removed": [json.loads(item) for item in sorted(left - right)],
                }
        if before["sha256"] != after["sha256"] or before.get("abi_id") != after.get("abi_id") or fact_changes:
            changes.append(
                {
                    "component_id": component_id,
                    "change": "modified",
                    "binary_changed": before["sha256"] != after["sha256"],
                    "abi_changed": before.get("abi_id") != after.get("abi_id"),
                    "fact_changes": fact_changes,
                }
            )
    report = {
        "schema_version": "rehostrace.target-differential/v1",
        "target_family": baseline["target_family"],
        "baseline_version": baseline["version"],
        "candidate_version": candidate["version"],
        "baseline_sha256": _digest(baseline),
        "candidate_sha256": _digest(candidate),
        "changes": changes,
        "summary": {
            "added": sum(item["change"] == "added" for item in changes),
            "removed": sum(item["change"] == "removed" for item in changes),
            "modified": sum(item["change"] == "modified" for item in changes),
        },
    }
    report["report_sha256"] = _digest(report)
    return report

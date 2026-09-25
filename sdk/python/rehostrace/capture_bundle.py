"""Compile passive boundary records into a causal trace.

Record order establishes program order only within one actor.  Cross-actor
edges must be present in ``causes``.  Clock values are copied as diagnostic
metadata and never manufacture happens-before edges.
"""

from __future__ import annotations

import copy
import hashlib
import json

from .model import canonical_sha256, validate_trace


def validate_capture_bundle(document: dict) -> dict:
    if document.get("schema_version") != "rehostrace.capture-bundle/v1":
        raise ValueError("unsupported capture bundle schema")
    if not isinstance(document.get("capture_id"), str) or not document["capture_id"]:
        raise ValueError("capture bundle requires capture_id")
    if document.get("disclosure") not in {"public-synthetic", "public-redacted", "private-product", "vendor-approved"}:
        raise ValueError("capture bundle has invalid disclosure")
    for name in ("actors", "clock_domains"):
        if not isinstance(document.get(name), list) or not document[name]:
            raise ValueError(f"capture bundle requires {name}")
    if not isinstance(document.get("resources", []), list):
        raise ValueError("capture bundle resources must be a list")
    records = document.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("capture bundle requires records")
    actor_ids = {item.get("id") for item in document["actors"] if isinstance(item, dict)}
    clock_ids = {item.get("id") for item in document["clock_domains"] if isinstance(item, dict)}
    resource_ids = {item.get("id") for item in document.get("resources", []) if isinstance(item, dict)}
    if len(actor_ids) != len(document["actors"]) or None in actor_ids:
        raise ValueError("capture actors must have unique ids")
    if len(clock_ids) != len(document["clock_domains"]) or None in clock_ids:
        raise ValueError("capture clocks must have unique ids")
    ids = [record.get("id") for record in records if isinstance(record, dict)]
    if len(ids) != len(records) or None in ids or len(ids) != len(set(ids)):
        raise ValueError("capture records must have unique ids")
    known = set(ids)
    for record in records:
        if record.get("actor") not in actor_ids:
            raise ValueError("capture record references unknown actor")
        boundary = record.get("boundary")
        if not isinstance(boundary, dict) or not all(
            isinstance(boundary.get(key), str) and boundary[key]
            for key in ("domain", "operation", "direction")
        ):
            raise ValueError("capture record has invalid boundary")
        causes = record.get("causes", [])
        if not isinstance(causes, list) or len(causes) != len(set(causes)) or any(
            cause not in known or cause == record["id"] for cause in causes
        ):
            raise ValueError("capture record causes are invalid")
        if "subject" in record and record["subject"] not in resource_ids:
            raise ValueError("capture record references unknown resource")
        if "clock" in record:
            clock = record["clock"]
            if not isinstance(clock, dict) or clock.get("domain") not in clock_ids:
                raise ValueError("capture record references unknown clock")
        if not isinstance(record.get("attributes", {}), dict):
            raise ValueError("capture record attributes must be an object")
        if "payload_hex" in record:
            value = record["payload_hex"]
            if not isinstance(value, str) or len(value) % 2:
                raise ValueError("payload_hex must contain whole bytes")
            try:
                bytes.fromhex(value)
            except ValueError as error:
                raise ValueError("payload_hex must be hexadecimal") from error
    return copy.deepcopy(document)


def compile_capture_bundle(document: dict) -> dict:
    bundle = validate_capture_bundle(document)
    last_by_actor: dict[str, str] = {}
    events: list[dict] = []
    for record in bundle["records"]:
        parents = set(record.get("causes", []))
        previous = last_by_actor.get(record["actor"])
        if previous is not None:
            parents.add(previous)
        event = {
            "id": record["id"],
            "actor": record["actor"],
            "kind": record.get("kind", "custom"),
            "boundary": copy.deepcopy(record["boundary"]),
            "parents": sorted(parents),
            "attributes": copy.deepcopy(record.get("attributes", {})),
        }
        for optional in ("subject", "correlation", "clock"):
            if optional in record:
                event[optional] = copy.deepcopy(record[optional])
        if "payload_hex" in record:
            payload = bytes.fromhex(record["payload_hex"])
            event["payload"] = {
                "length": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "encoding": "omitted",
            }
            if bundle["disclosure"] == "public-synthetic" and record.get("publish_payload") is True:
                event["payload"].update(encoding="hex", data=payload.hex())
        events.append(event)
        last_by_actor[record["actor"]] = record["id"]
    trace = {
        "schema_version": "rehostrace.causal/v2",
        "trace_id": bundle["capture_id"],
        "disclosure": bundle["disclosure"],
        "origin": {
            "kind": "translated",
            "producer": bundle.get("producer", "rehostrace-capture-compiler"),
            "source_hashes": [canonical_sha256(bundle)],
            "redactions": copy.deepcopy(bundle.get("redactions", [])),
        },
        "clock_domains": copy.deepcopy(bundle["clock_domains"]),
        "actors": copy.deepcopy(bundle["actors"]),
        "resources": copy.deepcopy(bundle.get("resources", [])),
        "events": events,
    }
    trace["integrity"] = {"canonical_sha256": canonical_sha256(trace)}
    validate_trace(trace)
    return trace

"""Canonical causal-trace model.

Timestamps are diagnostic metadata.  Only explicit parent edges establish a
happens-before relation.  This prevents unsynchronised device and host clocks
from silently serialising events that may have raced.
"""

from __future__ import annotations

import copy
import base64
import binascii
import hashlib
import json
import re
from collections import defaultdict
from typing import Iterable


ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
DISCLOSURES = {
    "public-synthetic",
    "public-redacted",
    "private-product",
    "vendor-approved",
}
ORIGIN_KINDS = {"synthetic", "live-capture", "translated", "replayed"}
ACTOR_KINDS = {
    "thread",
    "interrupt",
    "timer",
    "workqueue",
    "firmware",
    "host",
    "device",
    "tool",
    "unknown",
}
EVENT_KINDS = {
    "boundary.input",
    "boundary.output",
    "scheduler.point",
    "lifetime.alloc",
    "lifetime.free",
    "interrupt",
    "workqueue",
    "timeout",
    "link.state",
    "oracle.finding",
    "custom",
}
DIRECTIONS = {"target-in", "target-out", "internal", "observation"}
CLOCK_UNITS = {"ns", "us", "ms", "ticks", "sequence"}


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(f"{label} is not a canonical identifier")
    return value


def _unique(records: Iterable[dict], label: str) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for position, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"{label}[{position}] must be an object")
        record_id = _id(record.get("id"), f"{label}[{position}].id")
        if record_id in result:
            raise ValueError(f"duplicate {label} id: {record_id}")
        result[record_id] = record
    return result


def _canonical_copy(trace: dict) -> dict:
    normalized = copy.deepcopy(trace)
    normalized.pop("integrity", None)
    for key in ("clock_domains", "actors", "resources", "events"):
        if isinstance(normalized.get(key), list):
            normalized[key] = sorted(normalized[key], key=lambda item: item["id"])
    for event in normalized.get("events", []):
        event["parents"] = sorted(event["parents"])
    origin = normalized.get("origin", {})
    for key in ("source_hashes", "redactions"):
        if isinstance(origin.get(key), list):
            origin[key] = sorted(origin[key])
    return normalized


def canonical_bytes(document: dict) -> bytes:
    return json.dumps(
        _canonical_copy(document), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_sha256(document: dict) -> str:
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def validate_trace(trace: dict) -> dict:
    if not isinstance(trace, dict):
        raise ValueError("trace must be an object")
    if trace.get("schema_version") != "rehostrace.causal/v2":
        raise ValueError("schema_version must be rehostrace.causal/v2")
    trace_id = _id(trace.get("trace_id"), "trace_id")
    disclosure = trace.get("disclosure")
    if disclosure not in DISCLOSURES:
        raise ValueError("invalid disclosure")

    origin = trace.get("origin")
    if not isinstance(origin, dict) or origin.get("kind") not in ORIGIN_KINDS:
        raise ValueError("invalid origin")
    if not isinstance(origin.get("producer"), str) or not origin["producer"]:
        raise ValueError("origin.producer must be non-empty")
    for digest in origin.get("source_hashes", []):
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError("origin.source_hashes must contain SHA-256 digests")

    clocks = _unique(trace.get("clock_domains", []), "clock_domains")
    for clock_id, clock in clocks.items():
        if clock.get("unit") not in CLOCK_UNITS or type(clock.get("synchronized")) is not bool:
            raise ValueError(f"invalid clock domain: {clock_id}")

    actors = _unique(trace.get("actors", []), "actors")
    if not actors:
        raise ValueError("actors must not be empty")
    for actor_id, actor in actors.items():
        if actor.get("kind") not in ACTOR_KINDS:
            raise ValueError(f"invalid actor kind: {actor_id}")

    resources = _unique(trace.get("resources", []), "resources")
    for resource_id, resource in resources.items():
        if not isinstance(resource.get("kind"), str) or not resource["kind"]:
            raise ValueError(f"invalid resource kind: {resource_id}")
        if resource.get("identity") not in {"logical", "hash", "redacted", "opaque"}:
            raise ValueError(f"invalid resource identity: {resource_id}")

    event_list = trace.get("events")
    if not isinstance(event_list, list) or not 1 <= len(event_list) <= 65536:
        raise ValueError("events must contain between 1 and 65536 records")
    events = _unique(event_list, "events")
    children: dict[str, set[str]] = defaultdict(set)
    indegree = {event_id: 0 for event_id in events}

    for event_id, event in events.items():
        if event.get("actor") not in actors:
            raise ValueError(f"event {event_id} references an unknown actor")
        if event.get("kind") not in EVENT_KINDS:
            raise ValueError(f"event {event_id} has invalid kind")
        boundary = event.get("boundary")
        if not isinstance(boundary, dict):
            raise ValueError(f"event {event_id} boundary must be an object")
        if not isinstance(boundary.get("domain"), str) or not boundary["domain"]:
            raise ValueError(f"event {event_id} boundary.domain must be non-empty")
        if not isinstance(boundary.get("operation"), str) or not boundary["operation"]:
            raise ValueError(f"event {event_id} boundary.operation must be non-empty")
        if boundary.get("direction") not in DIRECTIONS:
            raise ValueError(f"event {event_id} has invalid boundary direction")
        if "subject" in event and event["subject"] not in resources:
            raise ValueError(f"event {event_id} references an unknown subject")
        if not isinstance(event.get("attributes"), dict):
            raise ValueError(f"event {event_id} attributes must be an object")
        parents = event.get("parents")
        if not isinstance(parents, list) or len(parents) != len(set(parents)):
            raise ValueError(f"event {event_id} parents must be a unique list")
        if event_id in parents:
            raise ValueError(f"event {event_id} cannot depend on itself")
        for parent in parents:
            if parent not in events:
                raise ValueError(f"event {event_id} references unknown parent {parent}")
            children[parent].add(event_id)
            indegree[event_id] += 1
        if "clock" in event:
            clock = event["clock"]
            if not isinstance(clock, dict) or clock.get("domain") not in clocks:
                raise ValueError(f"event {event_id} references an unknown clock domain")
            if type(clock.get("value")) is not int or clock["value"] < 0:
                raise ValueError(f"event {event_id} has invalid clock value")
            if "uncertainty" in clock and (
                type(clock["uncertainty"]) is not int or clock["uncertainty"] < 0
            ):
                raise ValueError(f"event {event_id} has invalid clock uncertainty")
        if "correlation" in event:
            correlation = event["correlation"]
            if not isinstance(correlation, dict) or any(
                not isinstance(key, str) or type(value) not in {str, int, bool}
                for key, value in correlation.items()
            ):
                raise ValueError(f"event {event_id} has invalid correlation data")
        if "payload" in event:
            payload = event["payload"]
            if not isinstance(payload, dict):
                raise ValueError(f"event {event_id} payload must be an object")
            if type(payload.get("length")) is not int or payload["length"] < 0:
                raise ValueError(f"event {event_id} payload length is invalid")
            if not isinstance(payload.get("sha256"), str) or not SHA256_RE.fullmatch(
                payload["sha256"]
            ):
                raise ValueError(f"event {event_id} payload digest is invalid")
            encoding = payload.get("encoding")
            if encoding not in {"omitted", "hex", "base64", "utf8"}:
                raise ValueError(f"event {event_id} payload encoding is invalid")
            if (encoding == "omitted") != ("data" not in payload):
                raise ValueError(f"event {event_id} payload data/encoding disagree")
            if disclosure == "public-redacted" and encoding != "omitted":
                raise ValueError("public-redacted traces cannot contain inline payloads")
            if encoding != "omitted":
                data = payload.get("data")
                if not isinstance(data, str):
                    raise ValueError(f"event {event_id} inline payload data must be text")
                try:
                    if encoding == "hex":
                        decoded = bytes.fromhex(data)
                    elif encoding == "base64":
                        decoded = base64.b64decode(data, validate=True)
                    else:
                        decoded = data.encode("utf-8")
                except (ValueError, UnicodeError, binascii.Error) as error:
                    raise ValueError(f"event {event_id} inline payload encoding is invalid") from error
                if len(decoded) != payload["length"]:
                    raise ValueError(f"event {event_id} inline payload length mismatch")
                if hashlib.sha256(decoded).hexdigest() != payload["sha256"]:
                    raise ValueError(f"event {event_id} inline payload digest mismatch")

    frontier = sorted(event_id for event_id, degree in indegree.items() if degree == 0)
    topological: list[str] = []
    layers: list[list[str]] = []
    remaining = dict(indegree)
    while frontier:
        layer = frontier
        layers.append(layer)
        topological.extend(layer)
        next_frontier: list[str] = []
        for event_id in layer:
            for child in sorted(children[event_id]):
                remaining[child] -= 1
                if remaining[child] == 0:
                    next_frontier.append(child)
        frontier = sorted(next_frontier)
    if len(topological) != len(events):
        cyclic = sorted(event_id for event_id, degree in remaining.items() if degree)
        raise ValueError(f"causal graph contains a cycle: {cyclic}")

    digest = canonical_sha256(trace)
    integrity = trace.get("integrity")
    if integrity is not None:
        if not isinstance(integrity, dict) or integrity.get("canonical_sha256") != digest:
            raise ValueError("integrity.canonical_sha256 does not match canonical trace")

    edge_count = sum(len(event["parents"]) for event in events.values())
    return {
        "status": "passed",
        "trace_id": trace_id,
        "canonical_sha256": digest,
        "event_count": len(events),
        "edge_count": edge_count,
        "topological_order": topological,
        "frontiers": layers,
    }


class CausalTrace:
    """Validated causal graph with happens-before and replay-frontier queries."""

    def __init__(self, trace: dict):
        self.document = copy.deepcopy(trace)
        self.validation = validate_trace(self.document)
        self.events = {event["id"]: event for event in self.document["events"]}
        self._parents = {event_id: set(event["parents"]) for event_id, event in self.events.items()}

    @property
    def digest(self) -> str:
        return self.validation["canonical_sha256"]

    def ready(self, completed: Iterable[str]) -> list[str]:
        done = set(completed)
        unknown = done - set(self.events)
        if unknown:
            raise ValueError(f"completed contains unknown events: {sorted(unknown)}")
        return sorted(
            event_id
            for event_id, parents in self._parents.items()
            if event_id not in done and parents <= done
        )

    def happens_before(self, first: str, second: str) -> bool:
        if first not in self.events or second not in self.events:
            raise KeyError(first if first not in self.events else second)
        pending = list(self._parents[second])
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            if current == first:
                return True
            if current not in visited:
                visited.add(current)
                pending.extend(self._parents[current])
        return False

    def concurrent(self, first: str, second: str) -> bool:
        return first != second and not self.happens_before(first, second) and not self.happens_before(
            second, first
        )

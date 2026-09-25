"""Boundary capture helpers that emit explicit causal edges."""

from __future__ import annotations

import base64
import copy
import hashlib
from typing import Any, Iterable

from .model import canonical_sha256, validate_trace


class CaptureSession:
    """Build a causal trace without deriving order from timestamps.

    Per-actor program order is chained by default. Cross-actor order must be
    supplied explicitly through ``parents``. Payload bytes are digest-only by
    default so product captures can be normalised without publishing secrets.
    """

    def __init__(self, trace_id: str, disclosure: str, origin_kind: str, producer: str):
        self._trace: dict[str, Any] = {
            "schema_version": "rehostrace.causal/v2",
            "trace_id": trace_id,
            "disclosure": disclosure,
            "origin": {"kind": origin_kind, "producer": producer, "redactions": []},
            "clock_domains": [],
            "actors": [],
            "resources": [],
            "events": [],
        }
        self._actors: set[str] = set()
        self._resources: set[str] = set()
        self._clocks: set[str] = set()
        self._last_by_actor: dict[str, str] = {}
        self._event_ids: set[str] = set()

    def add_clock(self, clock_id: str, unit: str, synchronized: bool, description: str = "") -> None:
        if clock_id in self._clocks:
            raise ValueError(f"duplicate clock: {clock_id}")
        record = {"id": clock_id, "unit": unit, "synchronized": synchronized}
        if description:
            record["description"] = description
        self._trace["clock_domains"].append(record)
        self._clocks.add(clock_id)

    def add_actor(self, actor_id: str, kind: str, description: str = "") -> None:
        if actor_id in self._actors:
            raise ValueError(f"duplicate actor: {actor_id}")
        record = {"id": actor_id, "kind": kind}
        if description:
            record["description"] = description
        self._trace["actors"].append(record)
        self._actors.add(actor_id)

    def add_resource(self, resource_id: str, kind: str, identity: str, description: str = "") -> None:
        if resource_id in self._resources:
            raise ValueError(f"duplicate resource: {resource_id}")
        record = {"id": resource_id, "kind": kind, "identity": identity}
        if description:
            record["description"] = description
        self._trace["resources"].append(record)
        self._resources.add(resource_id)

    def note_redaction(self, description: str) -> None:
        if description not in self._trace["origin"]["redactions"]:
            self._trace["origin"]["redactions"].append(description)

    @staticmethod
    def payload(data: bytes, include: bool = False, encoding: str = "base64") -> dict:
        record = {
            "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "encoding": "omitted",
        }
        if include:
            if encoding == "base64":
                record.update(encoding="base64", data=base64.b64encode(data).decode("ascii"))
            elif encoding == "hex":
                record.update(encoding="hex", data=data.hex())
            elif encoding == "utf8":
                record.update(encoding="utf8", data=data.decode("utf-8"))
            else:
                raise ValueError("encoding must be base64, hex, or utf8")
        return record

    def emit(
        self,
        event_id: str,
        actor: str,
        kind: str,
        domain: str,
        operation: str,
        direction: str,
        *,
        parents: Iterable[str] = (),
        chain_actor: bool = True,
        subject: str | None = None,
        correlation: dict | None = None,
        clock: dict | None = None,
        attributes: dict | None = None,
        payload: dict | None = None,
    ) -> None:
        if actor not in self._actors:
            raise ValueError(f"unknown actor: {actor}")
        if event_id in self._event_ids:
            raise ValueError(f"duplicate event: {event_id}")
        causal_parents = set(parents)
        if chain_actor and actor in self._last_by_actor:
            causal_parents.add(self._last_by_actor[actor])
        unknown = causal_parents - self._event_ids
        if unknown:
            raise ValueError(f"parents have not been emitted: {sorted(unknown)}")
        event: dict[str, Any] = {
            "id": event_id,
            "actor": actor,
            "kind": kind,
            "boundary": {"domain": domain, "operation": operation, "direction": direction},
            "parents": sorted(causal_parents),
            "attributes": copy.deepcopy(attributes or {}),
        }
        if subject is not None:
            event["subject"] = subject
        if correlation is not None:
            event["correlation"] = copy.deepcopy(correlation)
        if clock is not None:
            event["clock"] = copy.deepcopy(clock)
        if payload is not None:
            if self._trace["disclosure"] == "public-redacted" and payload.get("encoding") != "omitted":
                raise ValueError("public-redacted capture cannot inline payload bytes")
            event["payload"] = copy.deepcopy(payload)
        self._trace["events"].append(event)
        self._event_ids.add(event_id)
        self._last_by_actor[actor] = event_id

    def finish(self) -> dict:
        trace = copy.deepcopy(self._trace)
        trace["integrity"] = {"canonical_sha256": canonical_sha256(trace)}
        validate_trace(trace)
        return trace

"""Offline replay of a causal trace through a narrow boundary adapter."""

from __future__ import annotations

from typing import Protocol

from .model import CausalTrace


class ReplayError(RuntimeError):
    pass


class BoundaryAdapter(Protocol):
    def dispatch(self, event: dict) -> dict | None:
        """Apply one ready boundary event and return portable observation data."""


class RecordingAdapter:
    """Public reference adapter used to test ordering without target hardware."""

    def __init__(self):
        self.events: list[str] = []

    def dispatch(self, event: dict) -> dict:
        self.events.append(event["id"])
        return {
            "event_id": event["id"],
            "domain": event["boundary"]["domain"],
            "operation": event["boundary"]["operation"],
        }


class ReplayEngine:
    def __init__(self, trace: CausalTrace, adapter: BoundaryAdapter):
        self.trace = trace
        self.adapter = adapter

    def run(self, order: list[str] | None = None) -> dict:
        requested = order or list(self.trace.validation["topological_order"])
        if len(requested) != len(self.trace.events) or set(requested) != set(self.trace.events):
            raise ReplayError("replay order must contain every event exactly once")
        completed: list[str] = []
        observations: list[dict] = []
        for event_id in requested:
            ready = self.trace.ready(completed)
            if event_id not in ready:
                raise ReplayError(f"event {event_id} is not ready; frontier={ready}")
            result = self.adapter.dispatch(self.trace.events[event_id])
            completed.append(event_id)
            if result is not None:
                observations.append(result)
        return {
            "status": "passed",
            "trace_id": self.trace.document["trace_id"],
            "trace_sha256": self.trace.digest,
            "event_order": completed,
            "observations": observations,
        }

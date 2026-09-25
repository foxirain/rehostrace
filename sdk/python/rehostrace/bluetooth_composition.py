"""Composition and bounded linearization coverage for Bluetooth causal traces."""

from __future__ import annotations

import copy
import hashlib
import json
import random
from itertools import combinations

from .model import CausalTrace, ID_RE


NAMESPACED_ATTRIBUTE_KEYS = {
    "command_id",
    "sdu_id",
    "procedure_id",
    "address_token",
    "peer_address_token",
}


def _digest(document: dict) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_bluetooth_composition(document: dict) -> dict:
    if document.get("schema_version") != "rehostrace.bluetooth-composition/v1":
        raise ValueError("invalid Bluetooth composition schema_version")
    composition_id = document.get("composition_id")
    if not isinstance(composition_id, str) or not ID_RE.fullmatch(composition_id):
        raise ValueError("invalid Bluetooth composition_id")
    branches = document.get("branches")
    if not isinstance(branches, list) or len(branches) < 2:
        raise ValueError("Bluetooth composition requires at least two branches")
    if len(branches) > 8 or len(branches) != len(set(branches)):
        raise ValueError("Bluetooth composition branches must be 2..8 unique ids")
    if any(not isinstance(branch, str) or not ID_RE.fullmatch(branch) for branch in branches):
        raise ValueError("Bluetooth composition contains an invalid branch id")
    random_seeds = document.get("random_seeds")
    if (
        not isinstance(random_seeds, list)
        or not random_seeds
        or len(random_seeds) > 256
        or len(random_seeds) != len(set(random_seeds))
        or any(type(seed) is not int or seed < 0 or seed > 0xFFFFFFFF for seed in random_seeds)
    ):
        raise ValueError("random_seeds must be 1..256 unique 32-bit integers")
    if not isinstance(document.get("claim_boundary"), str) or not document["claim_boundary"]:
        raise ValueError("Bluetooth composition claim_boundary must be non-empty")
    return {
        "status": "passed",
        "composition_id": composition_id,
        "branch_count": len(branches),
        "random_seed_count": len(random_seeds),
        "composition_sha256": _digest(document),
    }


def _namespace_attributes(attributes: dict, branch: str) -> dict:
    result = copy.deepcopy(attributes)
    for key in NAMESPACED_ATTRIBUTE_KEYS:
        value = result.get(key)
        if isinstance(value, str):
            result[key] = f"{branch}:{value}"
    transaction_id = result.get("transaction_id")
    if isinstance(transaction_id, str):
        result["transaction_id"] = f"{branch}:{transaction_id}"
    return result


def compose_bluetooth_traces(document: dict, traces: dict[str, dict]) -> dict:
    """Merge independent profile traces under one shared controller-ready event."""

    validation = validate_bluetooth_composition(document)
    branches = document["branches"]
    if set(traces) != set(branches):
        raise ValueError("Bluetooth composition trace identities differ from its branches")

    parsed = {branch: CausalTrace(traces[branch]) for branch in branches}
    ready_by_branch: dict[str, dict] = {}
    handles: dict[int, str] = {}
    for branch, trace in parsed.items():
        ready = [
            event for event in trace.events.values()
            if event["boundary"]["operation"] == "hci.controller.ready"
        ]
        if len(ready) != 1:
            raise ValueError(f"branch {branch} must contain exactly one controller-ready event")
        ready_by_branch[branch] = ready[0]
        for event in trace.events.values():
            if event["boundary"]["operation"] in {
                "hci.connection.complete", "hci.le.connection.complete"
            }:
                handle = event["attributes"].get("handle")
                if handle in handles:
                    raise ValueError(
                        f"connection handle {handle!r} collides in branches "
                        f"{handles[handle]} and {branch}"
                    )
                handles[handle] = branch
    credits = {event["attributes"].get("command_credits") for event in ready_by_branch.values()}
    if len(credits) != 1:
        raise ValueError("composed branches disagree on controller command credits")

    clock_domains = [{"id": "shared.sequence", "unit": "sequence", "synchronized": False}]
    actors = [{"id": "shared.controller", "kind": "interrupt"}]
    resources = [{
        "id": "shared.controller-resource",
        "kind": "synthetic-bluetooth-controller",
        "identity": "logical",
    }]
    events = [{
        "id": "shared.controller-ready",
        "actor": "shared.controller",
        "kind": "link.state",
        "boundary": {
            "domain": "bluetooth.host-boundary",
            "operation": "hci.controller.ready",
            "direction": "target-in",
        },
        "parents": [],
        "subject": "shared.controller-resource",
        "clock": {"domain": "shared.sequence", "value": 1},
        "attributes": {"command_credits": next(iter(credits))},
    }]

    for branch in branches:
        trace = parsed[branch]
        ready_id = ready_by_branch[branch]["id"]
        actor_map = {actor["id"]: f"{branch}:{actor['id']}" for actor in trace.document["actors"]}
        resource_map = {
            resource["id"]: f"{branch}:{resource['id']}"
            for resource in trace.document["resources"]
        }
        clock_map = {
            clock["id"]: f"{branch}:{clock['id']}"
            for clock in trace.document["clock_domains"]
        }
        for clock in trace.document["clock_domains"]:
            clock_domains.append({**copy.deepcopy(clock), "id": clock_map[clock["id"]]})
        for actor in trace.document["actors"]:
            actors.append({**copy.deepcopy(actor), "id": actor_map[actor["id"]]})
        for resource in trace.document["resources"]:
            resources.append({**copy.deepcopy(resource), "id": resource_map[resource["id"]]})
        for source in trace.document["events"]:
            if source["id"] == ready_id:
                continue
            event = copy.deepcopy(source)
            event["id"] = f"{branch}:{source['id']}"
            event["actor"] = actor_map[source["actor"]]
            event["parents"] = [
                "shared.controller-ready" if parent == ready_id else f"{branch}:{parent}"
                for parent in source["parents"]
            ]
            if "subject" in source:
                event["subject"] = resource_map[source["subject"]]
            if "clock" in source:
                event["clock"]["domain"] = clock_map[source["clock"]["domain"]]
            event["attributes"] = _namespace_attributes(source["attributes"], branch)
            event.setdefault("correlation", {})["composition_branch"] = branch
            event["correlation"]["source_event"] = source["id"]
            events.append(event)

    result = {
        "schema_version": "rehostrace.causal/v2",
        "trace_id": document["composition_id"],
        "disclosure": "public-synthetic",
        "origin": {
            "kind": "translated",
            "producer": "rehostrace-bluetooth-composition",
            "source_hashes": sorted(trace.digest for trace in parsed.values()),
            "redactions": [],
        },
        "clock_domains": clock_domains,
        "actors": actors,
        "resources": resources,
        "events": events,
        "composition": {
            "source_sha256": validation["composition_sha256"],
            "branches": list(branches),
            "claim_boundary": document["claim_boundary"],
        },
    }
    CausalTrace(result)
    return result


def _frontier_order(trace: CausalTrace, *, reverse: bool = False, seed: int | None = None) -> list[str]:
    completed: list[str] = []
    generator = random.Random(seed) if seed is not None else None
    while len(completed) < len(trace.events):
        frontier = trace.ready(completed)
        if generator is not None:
            selected = generator.choice(frontier)
        else:
            selected = frontier[-1] if reverse else frontier[0]
        completed.append(selected)
    return completed


def _round_robin_order(trace: CausalTrace, branches: list[str]) -> list[str]:
    """Choose one ready event per branch while preserving the causal frontier."""

    completed: list[str] = []
    cursor = 0
    while len(completed) < len(trace.events):
        frontier = trace.ready(completed)
        selected = None
        for offset in range(len(branches)):
            index = (cursor + offset) % len(branches)
            branch = branches[index]
            candidates = [
                event_id for event_id in frontier
                if trace.events[event_id].get("correlation", {}).get(
                    "composition_branch"
                ) == branch
            ]
            if candidates:
                selected = candidates[0]
                cursor = (index + 1) % len(branches)
                break
        if selected is None:
            selected = frontier[0]
        completed.append(selected)
    return completed


def generate_bluetooth_linearizations(
    trace: CausalTrace, composition: dict
) -> list[dict]:
    """Generate bounded deterministic policies, deduplicating identical orders."""

    validation = validate_bluetooth_composition(composition)
    candidates = [
        ("frontier-min", _frontier_order(trace)),
        ("frontier-max", _frontier_order(trace, reverse=True)),
        ("round-robin", _round_robin_order(trace, composition["branches"])),
        *(
            (f"random-{seed:08x}", _frontier_order(trace, seed=seed))
            for seed in composition["random_seeds"]
        ),
    ]
    seen: set[tuple[str, ...]] = set()
    result: list[dict] = []
    for policy_id, order in candidates:
        key = tuple(order)
        if key in seen:
            continue
        seen.add(key)
        result.append({
            "policy_id": policy_id,
            "event_order": order,
            "event_order_sha256": hashlib.sha256("\n".join(order).encode()).hexdigest(),
        })
    if len(result) < 2:
        raise ValueError("Bluetooth composition did not yield distinct linearizations")
    for policy in result:
        if len(policy["event_order"]) != validation.get("event_count", len(trace.events)):
            raise AssertionError("generated Bluetooth order has the wrong cardinality")
    return result


def linearization_pair_coverage(trace: CausalTrace, policies: list[dict]) -> dict:
    positions = [
        {event_id: index for index, event_id in enumerate(policy["event_order"])}
        for policy in policies
    ]
    concurrent_pairs = [
        (first, second)
        for first, second in combinations(sorted(trace.events), 2)
        if trace.concurrent(first, second)
    ]
    reversed_pairs = [
        (first, second)
        for first, second in concurrent_pairs
        if {position[first] < position[second] for position in positions} == {True, False}
    ]
    return {
        "concurrent_pair_count": len(concurrent_pairs),
        "both_orders_observed": len(reversed_pairs),
        "both_orders_fraction": (
            len(reversed_pairs) / len(concurrent_pairs) if concurrent_pairs else 1.0
        ),
        "all_concurrent_pairs_reversed": len(reversed_pairs) == len(concurrent_pairs),
    }

"""Allocation-provenance oracle for same-address lifetime reuse.

The ordinary lifetime oracle answers whether multiple sinks observed the same
object token.  This module answers the next question: did a boundary event make
the target allocate a *new generation* at the freed address before a stale path
read, mutated state with, and freed that new owner?

Addresses are intentionally represented as adapter-issued opaque tokens.  A
target integration may hash or otherwise redact raw addresses while preserving
equality and generation relationships.
"""

from __future__ import annotations

from collections import Counter

from .model import ID_RE


ROLE_NAMES = {
    "original_free",
    "boundary_input",
    "replacement_alloc",
    "stale_read",
    "list_write",
    "foreign_free",
}
OPTIONAL_ROLE_NAMES = {"post_free_alias"}
REQUIRED_SEQUENCE = [
    "original_free",
    "boundary_input",
    "replacement_alloc",
    "stale_read",
    "list_write",
    "foreign_free",
]
DISCLOSURES = {"public-synthetic", "private-product", "vendor-approved"}
OBSERVATION_TYPES = {
    "original_free": "lifetime.free",
    "boundary_input": "boundary.input",
    "replacement_alloc": "lifetime.alloc",
    "stale_read": "memory.read",
    "list_write": "memory.write",
    "foreign_free": "lifetime.free",
    "post_free_alias": "lifetime.alloc",
}


def _canonical_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(f"{label} must be a canonical identifier")
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be non-empty text")
    return value


def validate_reclaim_oracle(oracle: dict) -> dict:
    """Validate a target-owned reclaim and foreign-free evidence contract."""

    if (
        not isinstance(oracle, dict)
        or oracle.get("schema_version") != "rehostrace.reclaim-oracle/v1"
    ):
        raise ValueError("invalid reclaim oracle schema_version")
    oracle_id = _canonical_id(oracle.get("oracle_id"), "oracle_id")
    if oracle.get("disclosure") not in DISCLOSURES:
        raise ValueError("invalid reclaim oracle disclosure")

    roles = oracle.get("roles")
    if not isinstance(roles, dict):
        raise ValueError("roles must be an object")
    role_names = set(roles)
    missing = ROLE_NAMES - role_names
    unknown = role_names - ROLE_NAMES - OPTIONAL_ROLE_NAMES
    if missing or unknown:
        raise ValueError(
            f"roles differ from the reclaim contract: missing={sorted(missing)} "
            f"unknown={sorted(unknown)}"
        )
    role_ids: set[str] = set()
    for role, observation_id in roles.items():
        value = _canonical_id(observation_id, f"roles.{role}")
        if value in role_ids:
            raise ValueError("reclaim role observation ids must be unique")
        role_ids.add(value)

    required_sequence = oracle.get("required_sequence")
    expected_sequence = REQUIRED_SEQUENCE + (
        ["post_free_alias"] if "post_free_alias" in roles else []
    )
    if required_sequence != expected_sequence:
        raise ValueError(
            "required_sequence must match the canonical reclaim sequence: "
            + ", ".join(expected_sequence)
        )

    provenance = oracle.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("provenance must be an object")
    required_producer = _canonical_id(
        provenance.get("replacement_producer"),
        "provenance.replacement_producer",
    )
    forbidden = provenance.get("forbidden_producers")
    if (
        not isinstance(forbidden, list)
        or len(forbidden) != len(set(forbidden))
        or any(not isinstance(item, str) or not ID_RE.fullmatch(item) for item in forbidden)
    ):
        raise ValueError("provenance.forbidden_producers must contain unique ids")
    if required_producer in forbidden:
        raise ValueError("required replacement producer cannot also be forbidden")
    _canonical_id(provenance.get("origin_event"), "provenance.origin_event")
    _canonical_id(provenance.get("origin_operation"), "provenance.origin_operation")
    _canonical_id(provenance.get("allocation_callsite"), "provenance.allocation_callsite")
    size_class = provenance.get("size_class")
    if type(size_class) is not int or not 1 <= size_class <= 1 << 30:
        raise ValueError("provenance.size_class must be a positive integer")

    ownership = oracle.get("ownership")
    if not isinstance(ownership, dict):
        raise ValueError("ownership must be an object")
    for field in ("original_owner", "replacement_owner", "stale_actor"):
        _canonical_id(ownership.get(field), f"ownership.{field}")
    if ownership["original_owner"] == ownership["replacement_owner"]:
        raise ValueError("original and replacement owners must differ")
    if ownership["stale_actor"] == ownership["replacement_owner"]:
        raise ValueError("stale actor cannot be the replacement owner")

    effects = oracle.get("effects")
    if not isinstance(effects, dict):
        raise ValueError("effects must be an object")
    offset = effects.get("stale_read_offset")
    if type(offset) is not int or offset < 0:
        raise ValueError("effects.stale_read_offset must be a non-negative integer")
    _canonical_id(effects.get("list_write_target"), "effects.list_write_target")
    if effects.get("value_relation") != "read-to-write":
        raise ValueError("effects.value_relation must be read-to-write")

    forbidden_events = oracle.get("forbidden_events")
    if (
        not isinstance(forbidden_events, list)
        or len(forbidden_events) != len(set(forbidden_events))
        or any(not isinstance(item, str) or not ID_RE.fullmatch(item) for item in forbidden_events)
    ):
        raise ValueError("forbidden_events must contain unique canonical ids")
    _nonempty(oracle.get("claim_boundary"), "claim_boundary")

    return {
        "status": "passed",
        "oracle_id": oracle_id,
        "role_count": len(roles),
        "requires_post_free_alias": "post_free_alias" in roles,
        "replacement_producer": required_producer,
        "size_class": size_class,
    }


def _token(record: dict, field: str) -> str | None:
    value = record.get(field)
    return value if isinstance(value, str) and bool(value) else None


def evaluate_reclaim_oracle(oracle: dict, observations: list[dict]) -> dict:
    """Evaluate same-address reuse with boundary and allocation provenance.

    Missing or malformed required observations are inconclusive.  Complete
    observations that contradict the policy are negative.  This distinction
    prevents missing target instrumentation from being reported as a clean run.
    """

    validation = validate_reclaim_oracle(oracle)
    if not isinstance(observations, list):
        raise ValueError("observations must be a list")

    indexed: dict[str, dict] = {}
    malformed: list[int] = []
    duplicate_ids: list[str] = []
    event_counts: Counter[str] = Counter()
    for index, record in enumerate(observations):
        if not isinstance(record, dict):
            malformed.append(index)
            continue
        observation_id = record.get("id")
        sequence = record.get("sequence")
        kind = record.get("type")
        if (
            not isinstance(observation_id, str)
            or not ID_RE.fullmatch(observation_id)
            or type(sequence) is not int
            or sequence < 0
            or not isinstance(kind, str)
        ):
            malformed.append(index)
            continue
        if observation_id in indexed:
            duplicate_ids.append(observation_id)
            malformed.append(index)
            continue
        indexed[observation_id] = record
        if kind == "event" and isinstance(record.get("name"), str):
            event_counts[record["name"]] += 1

    roles = oracle["roles"]
    resolved = {role: indexed.get(observation_id) for role, observation_id in roles.items()}
    complete = not malformed and all(record is not None for record in resolved.values())
    checks: dict[str, bool] = {}
    for role, record in resolved.items():
        checks[f"present:{role}"] = record is not None
        checks[f"type:{role}"] = bool(
            record and record.get("type") == OBSERVATION_TYPES[role]
        )

    ordered_records = [resolved[role] for role in oracle["required_sequence"]]
    checks["sequence:required"] = bool(
        all(record is not None for record in ordered_records)
        and all(
            ordered_records[index]["sequence"] < ordered_records[index + 1]["sequence"]
            for index in range(len(ordered_records) - 1)
        )
    )

    original = resolved["original_free"] or {}
    boundary = resolved["boundary_input"] or {}
    replacement = resolved["replacement_alloc"] or {}
    stale_read = resolved["stale_read"] or {}
    list_write = resolved["list_write"] or {}
    foreign_free = resolved["foreign_free"] or {}
    alias = resolved.get("post_free_alias") or {}

    object_records = [original, replacement, stale_read, foreign_free]
    if "post_free_alias" in roles:
        object_records.append(alias)
    object_tokens = [_token(record, "object") for record in object_records]
    checks["identity:same-address"] = bool(
        all(object_tokens) and len(set(object_tokens)) == 1
    )

    original_generation = _token(original, "generation")
    replacement_generation = _token(replacement, "generation")
    replacement_generations = [
        replacement_generation,
        _token(stale_read, "generation"),
        _token(foreign_free, "generation"),
    ]
    checks["identity:new-generation"] = bool(
        original_generation
        and replacement_generation
        and original_generation != replacement_generation
    )
    checks["identity:replacement-generation-continuity"] = bool(
        all(replacement_generations) and len(set(replacement_generations)) == 1
    )
    if "post_free_alias" in roles:
        alias_generation = _token(alias, "generation")
        checks["identity:post-free-new-generation"] = bool(
            alias_generation
            and replacement_generation
            and alias_generation != replacement_generation
        )

    provenance = oracle["provenance"]
    checks["provenance:boundary-event"] = bool(
        boundary.get("event_id") == provenance["origin_event"]
        and replacement.get("origin_event") == boundary.get("event_id")
    )
    checks["provenance:boundary-operation"] = bool(
        boundary.get("operation") == provenance["origin_operation"]
        and replacement.get("origin_operation") == boundary.get("operation")
    )
    checks["provenance:target-producer"] = bool(
        replacement.get("producer") == provenance["replacement_producer"]
        and replacement.get("producer") not in provenance["forbidden_producers"]
    )
    checks["provenance:size-class"] = (
        replacement.get("size_class") == provenance["size_class"]
    )
    checks["provenance:allocation-callsite"] = (
        replacement.get("callsite") == provenance["allocation_callsite"]
    )

    ownership = oracle["ownership"]
    checks["ownership:original"] = original.get("owner") == ownership["original_owner"]
    checks["ownership:replacement"] = all(
        record.get("owner") == ownership["replacement_owner"]
        for record in (replacement, stale_read, foreign_free)
    )
    checks["ownership:stale-actor"] = all(
        record.get("actor") == ownership["stale_actor"]
        for record in (stale_read, list_write, foreign_free)
    )
    checks["ownership:foreign-free"] = bool(
        foreign_free.get("owner") == ownership["replacement_owner"]
        and foreign_free.get("actor") == ownership["stale_actor"]
        and foreign_free.get("actor") != foreign_free.get("owner")
    )

    effects = oracle["effects"]
    read_value = _token(stale_read, "value")
    checks["effect:stale-read-offset"] = (
        stale_read.get("offset") == effects["stale_read_offset"]
    )
    checks["effect:list-write-target"] = (
        list_write.get("target") == effects["list_write_target"]
    )
    checks["effect:read-to-write"] = bool(
        read_value
        and list_write.get("value") == read_value
        and list_write.get("source_observation") == roles["stale_read"]
    )

    for forbidden in oracle["forbidden_events"]:
        checks[f"forbidden:{forbidden}"] = event_counts[forbidden] == 0

    if complete and all(checks.values()):
        verdict = "positive"
    elif not complete:
        verdict = "inconclusive"
    else:
        verdict = "negative"

    identity_tokens = sorted({token for token in object_tokens if token is not None})
    generation_tokens = sorted(
        {
            token
            for token in (
                original_generation,
                replacement_generation,
                _token(alias, "generation") if alias else None,
            )
            if token is not None
        }
    )
    return {
        "oracle_id": validation["oracle_id"],
        "verdict": verdict,
        "checks": dict(sorted(checks.items())),
        "identity_tokens": identity_tokens,
        "generation_tokens": generation_tokens,
        "replacement_producer": replacement.get("producer"),
        "replacement_origin_event": replacement.get("origin_event"),
        "observation_count": len(observations),
        "malformed_observations": malformed,
        "duplicate_observation_ids": sorted(set(duplicate_ids)),
    }

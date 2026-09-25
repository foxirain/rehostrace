"""Generic object-lifetime oracle over portable observation records."""

from __future__ import annotations

from collections import Counter, defaultdict

from .model import ID_RE


def validate_oracle(oracle: dict) -> dict:
    if not isinstance(oracle, dict) or oracle.get("schema_version") != "rehostrace.oracle/v1":
        raise ValueError("invalid oracle schema_version")
    oracle_id = oracle.get("oracle_id")
    if not isinstance(oracle_id, str) or not ID_RE.fullmatch(oracle_id):
        raise ValueError("invalid oracle_id")
    identity = oracle.get("identity")
    if not isinstance(identity, dict) or identity.get("relation") != "equal":
        raise ValueError("identity relation must be equal")
    capture = identity.get("capture")
    if not isinstance(capture, str) or not ID_RE.fullmatch(capture):
        raise ValueError("invalid identity capture")
    points = identity.get("points")
    if not isinstance(points, list) or len(points) < 2 or len(points) != len(set(points)):
        raise ValueError("identity points must contain at least two unique ids")
    required_ids: set[str] = set()
    for record in oracle.get("required_points", []):
        point_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(point_id, str) or not ID_RE.fullmatch(point_id):
            raise ValueError("invalid required point")
        if point_id in required_ids:
            raise ValueError(f"duplicate required point: {point_id}")
        minimum = record.get("min_hits")
        maximum = record.get("max_hits")
        if type(minimum) is not int or minimum < 1:
            raise ValueError(f"invalid min_hits: {point_id}")
        if maximum is not None and (type(maximum) is not int or maximum < minimum):
            raise ValueError(f"invalid max_hits: {point_id}")
        required_ids.add(point_id)
    for point_id in points:
        if point_id not in required_ids:
            raise ValueError(f"identity point is not required: {point_id}")
    counter_ids: set[str] = set()
    for record in oracle.get("counters", []):
        counter_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(counter_id, str) or not ID_RE.fullmatch(counter_id):
            raise ValueError("invalid oracle counter")
        if counter_id in counter_ids:
            raise ValueError(f"duplicate oracle counter: {counter_id}")
        minimum = record.get("minimum")
        maximum = record.get("maximum")
        if type(minimum) is not int or minimum < 0:
            raise ValueError(f"invalid counter minimum: {counter_id}")
        if maximum is not None and (type(maximum) is not int or maximum < minimum):
            raise ValueError(f"invalid counter maximum: {counter_id}")
        counter_ids.add(counter_id)
    sanitizer = oracle.get("sanitizer")
    if not isinstance(sanitizer, dict) or type(sanitizer.get("required")) is not bool:
        raise ValueError("invalid sanitizer policy")
    return {
        "status": "passed",
        "oracle_id": oracle_id,
        "required_point_count": len(required_ids),
        "counter_count": len(counter_ids),
    }


def evaluate_oracle(oracle: dict, observations: list[dict]) -> dict:
    validate_oracle(oracle)
    point_hits: Counter[str] = Counter()
    captures: dict[str, list[str]] = defaultdict(list)
    counters: dict[str, int] = {}
    events: Counter[str] = Counter()
    sanitizers: list[dict] = []
    malformed: list[int] = []

    for index, observation in enumerate(observations):
        if not isinstance(observation, dict) or not isinstance(observation.get("type"), str):
            malformed.append(index)
            continue
        kind = observation["type"]
        if kind == "point":
            point = observation.get("point")
            if not isinstance(point, str):
                malformed.append(index)
                continue
            point_hits[point] += 1
            for key, value in observation.get("captures", {}).items():
                if isinstance(key, str) and isinstance(value, str):
                    captures[f"{point}:{key}"].append(value)
        elif kind == "counter":
            name, value = observation.get("name"), observation.get("value")
            if not isinstance(name, str) or type(value) is not int:
                malformed.append(index)
                continue
            counters[name] = value
        elif kind == "event":
            name = observation.get("name")
            if not isinstance(name, str):
                malformed.append(index)
                continue
            events[name] += 1
        elif kind == "sanitizer":
            if not isinstance(observation.get("kind"), str) or not isinstance(
                observation.get("frames"), list
            ):
                malformed.append(index)
                continue
            sanitizers.append(observation)
        else:
            malformed.append(index)

    checks: dict[str, bool] = {}
    complete = not malformed
    for required in oracle["required_points"]:
        count = point_hits[required["id"]]
        passed = count >= required["min_hits"] and (
            "max_hits" not in required or count <= required["max_hits"]
        )
        checks[f"point:{required['id']}"] = passed
        # A missing required multiplicity is an evidence gap, not evidence that
        # the lifetime property is false.  For example, observing only one of
        # two required free entries must remain inconclusive.
        complete = complete and count >= required["min_hits"]

    identity = oracle["identity"]
    tokens: list[str] = []
    identity_complete = True
    for point in identity["points"]:
        found = captures.get(f"{point}:{identity['capture']}", [])
        if not found:
            identity_complete = False
        tokens.extend(found)
    checks["identity:equal"] = identity_complete and len(set(tokens)) == 1
    complete = complete and identity_complete

    for required in oracle["counters"]:
        value = counters.get(required["id"])
        passed = value is not None and value >= required["minimum"] and (
            "maximum" not in required or value <= required["maximum"]
        )
        checks[f"counter:{required['id']}"] = passed
        complete = complete and value is not None

    for forbidden in oracle["forbidden_events"]:
        checks[f"forbidden:{forbidden}"] = events[forbidden] == 0

    sanitizer = oracle["sanitizer"]
    kinds = set(sanitizer["kinds"])
    matching = [record for record in sanitizers if record["kind"] in kinds]
    checks["sanitizer:kind"] = bool(matching) if sanitizer["required"] else True
    frame_text = "\n".join(
        frame for record in matching for frame in record.get("frames", []) if isinstance(frame, str)
    )
    checks["sanitizer:frames"] = all(
        required in frame_text for required in sanitizer["required_frames"]
    )
    if sanitizer["required"]:
        complete = complete and bool(sanitizers)

    if complete and all(checks.values()):
        verdict = "positive"
    elif not complete:
        verdict = "inconclusive"
    else:
        verdict = "negative"
    return {
        "oracle_id": oracle["oracle_id"],
        "verdict": verdict,
        "checks": dict(sorted(checks.items())),
        "identity_tokens": sorted(set(tokens)),
        "observation_count": len(observations),
        "malformed_observations": malformed,
        "point_hits": dict(sorted(point_hits.items())),
        "counters": dict(sorted(counters.items())),
    }

"""Bounded, evidence-driven search over semantic schedule gates."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import math
from collections import defaultdict

from .binding import compile_binding
from .model import CausalTrace, ID_RE, SHA256_RE
from .synthesis import synthesize_schedule, validate_constraints


def _digest(document: dict) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float]:
    if total == 0:
        return [0.0, 0.0]
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total))
        / denominator
    )
    return [max(0.0, center - margin), min(1.0, center + margin)]


def gate_key(gate: dict) -> str:
    """Return the stable semantic identity of one release gate."""

    if not isinstance(gate, dict):
        raise ValueError("gate must be an object")
    signal = gate.get("after_signal")
    target = gate.get("before_release_of")
    if not isinstance(signal, str) or not ID_RE.fullmatch(signal):
        raise ValueError("gate after_signal must be a canonical id")
    if not isinstance(target, str) or not ID_RE.fullmatch(target):
        raise ValueError("gate before_release_of must be a canonical id")
    return f"{signal}::{target}"


def _candidate_constraints(base: dict, enabled: set[str]) -> dict:
    candidate = copy.deepcopy(base)
    candidate["gates"] = [gate for gate in base["gates"] if gate_key(gate) in enabled]
    return candidate


def plan_exhaustive_search(
    constraints: dict,
    binding: dict,
    trace: CausalTrace,
    *,
    search_id: str,
    repetitions: int,
    max_gates: int = 12,
) -> tuple[dict, dict[str, dict]]:
    """Enumerate every gate subset and bind each resulting schedule.

    This is intentionally bounded.  It proves global minimality only within the
    declared gate universe; it does not discover points or precedence edges.
    """

    validation = validate_constraints(constraints)
    if not isinstance(search_id, str) or not ID_RE.fullmatch(search_id):
        raise ValueError("invalid search_id")
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("repetitions must be positive")
    keys = sorted(gate_key(gate) for gate in constraints["gates"])
    if len(keys) != len(set(keys)):
        raise ValueError("gate universe contains duplicate semantic gates")
    if len(keys) > max_gates:
        raise ValueError(f"exhaustive search is bounded to {max_gates} gates")

    documents: dict[str, dict] = {}
    candidates: list[dict] = []
    universe = set(keys)
    for count in range(len(keys) + 1):
        for combination in itertools.combinations(keys, count):
            enabled = set(combination)
            candidate_constraints = _candidate_constraints(constraints, enabled)
            schedule, synthesis = synthesize_schedule(candidate_constraints)
            candidate_binding = copy.deepcopy(binding)
            candidate_binding["schedule_sha256"] = synthesis["schedule_sha256"]
            binding_plan = compile_binding(candidate_binding, trace, schedule)
            candidate_id = f"candidate.{_digest(candidate_constraints)[:16]}"
            documents[candidate_id] = {
                "constraints": candidate_constraints,
                "schedule": schedule,
                "binding": candidate_binding,
                "synthesis": synthesis,
            }
            candidates.append(
                {
                    "candidate_id": candidate_id,
                    "enabled_gates": sorted(enabled),
                    "disabled_gates": sorted(universe - enabled),
                    "gate_count": len(enabled),
                    "constraints_sha256": synthesis["constraints_sha256"],
                    "schedule_sha256": synthesis["schedule_sha256"],
                    "binding_sha256": binding_plan["binding_sha256"],
                }
            )

    manifest = {
        "schema_version": "rehostrace.schedule-search/v1",
        "search_id": search_id,
        "strategy": "exhaustive-gate-subsets",
        "repetitions_per_candidate": repetitions,
        "base_constraints_sha256": validation["constraints_sha256"],
        "trace_sha256": trace.digest,
        "gate_universe": keys,
        "candidates": candidates,
        "claim_boundary": (
            "Global minimality is evaluated only over the declared gate universe. "
            "Semantic point discovery and new precedence-edge discovery are out of scope."
        ),
    }
    validate_search_manifest(manifest)
    return manifest, documents


def validate_search_manifest(manifest: dict) -> dict:
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "rehostrace.schedule-search/v1"
    ):
        raise ValueError("invalid schedule-search schema_version")
    if not isinstance(manifest.get("search_id"), str) or not ID_RE.fullmatch(
        manifest["search_id"]
    ):
        raise ValueError("invalid search_id")
    if manifest.get("strategy") != "exhaustive-gate-subsets":
        raise ValueError("unsupported search strategy")
    repetitions = manifest.get("repetitions_per_candidate")
    if type(repetitions) is not int or repetitions < 1:
        raise ValueError("invalid repetitions_per_candidate")
    universe = manifest.get("gate_universe")
    if (
        not isinstance(universe, list)
        or len(universe) != len(set(universe))
        or any(not isinstance(key, str) or "::" not in key for key in universe)
    ):
        raise ValueError("invalid gate universe")
    for field in ("base_constraints_sha256", "trace_sha256"):
        if not isinstance(manifest.get(field), str) or not SHA256_RE.fullmatch(manifest[field]):
            raise ValueError(f"invalid {field}")
    if not isinstance(manifest.get("claim_boundary"), str) or not manifest["claim_boundary"]:
        raise ValueError("search claim_boundary must be non-empty")

    seen: set[str] = set()
    subsets: set[tuple[str, ...]] = set()
    records = manifest.get("candidates")
    if not isinstance(records, list) or not records:
        raise ValueError("search manifest must contain candidates")
    for record in records:
        candidate_id = record.get("candidate_id") if isinstance(record, dict) else None
        if (
            not isinstance(candidate_id, str)
            or not ID_RE.fullmatch(candidate_id)
            or candidate_id in seen
        ):
            raise ValueError("candidate ids must be unique canonical ids")
        enabled = record.get("enabled_gates")
        disabled = record.get("disabled_gates")
        if (
            not isinstance(enabled, list)
            or not isinstance(disabled, list)
            or enabled != sorted(enabled)
            or disabled != sorted(disabled)
            or set(enabled) & set(disabled)
            or set(enabled) | set(disabled) != set(universe)
            or record.get("gate_count") != len(enabled)
        ):
            raise ValueError(f"invalid gate partition: {candidate_id}")
        subset = tuple(enabled)
        if subset in subsets:
            raise ValueError("duplicate gate subset")
        for field in ("constraints_sha256", "schedule_sha256", "binding_sha256"):
            if not isinstance(record.get(field), str) or not SHA256_RE.fullmatch(record[field]):
                raise ValueError(f"invalid candidate digest: {candidate_id}.{field}")
        seen.add(candidate_id)
        subsets.add(subset)
    expected = 1 << len(universe)
    if len(records) != expected or len(subsets) != expected:
        raise ValueError(f"exhaustive manifest requires {expected} unique subsets")
    return {
        "status": "passed",
        "search_id": manifest["search_id"],
        "gate_count": len(universe),
        "candidate_count": len(records),
        "manifest_sha256": _digest(manifest),
    }


def summarize_search(manifest: dict, trials: list[dict]) -> dict:
    """Classify repeated outcomes and select a globally minimal positive set."""

    validation = validate_search_manifest(manifest)
    repetitions = manifest["repetitions_per_candidate"]
    candidates = {record["candidate_id"]: record for record in manifest["candidates"]}
    grouped: dict[str, list[dict]] = defaultdict(list)
    seen_runs: set[tuple[str, int]] = set()
    for trial in trials:
        candidate_id = trial.get("candidate_id") if isinstance(trial, dict) else None
        run = trial.get("run") if isinstance(trial, dict) else None
        verdict = trial.get("verdict") if isinstance(trial, dict) else None
        if candidate_id not in candidates:
            raise ValueError(f"trial references unknown candidate: {candidate_id}")
        if type(run) is not int or not 1 <= run <= repetitions:
            raise ValueError(f"invalid trial run: {candidate_id}, {run}")
        if verdict not in {"positive", "negative", "inconclusive"}:
            raise ValueError(f"invalid trial verdict: {candidate_id}, {run}")
        key = (candidate_id, run)
        if key in seen_runs:
            raise ValueError(f"duplicate trial: {candidate_id}, {run}")
        receipt = trial.get("receipt_content_sha256")
        if receipt is not None and (
            not isinstance(receipt, str) or not SHA256_RE.fullmatch(receipt)
        ):
            raise ValueError(f"invalid trial receipt hash: {candidate_id}, {run}")
        seen_runs.add(key)
        grouped[candidate_id].append(copy.deepcopy(trial))

    results = []
    qualified: list[dict] = []
    incomplete = False
    for candidate in manifest["candidates"]:
        records = grouped[candidate["candidate_id"]]
        counts = {
            verdict: sum(record["verdict"] == verdict for record in records)
            for verdict in ("positive", "negative", "inconclusive")
        }
        complete = len(records) == repetitions
        stable_positive = complete and counts["positive"] == repetitions
        disposition = (
            "qualified-positive"
            if stable_positive
            else "inconclusive"
            if not complete or counts["inconclusive"]
            else "not-stable-positive"
        )
        result = {
            **candidate,
            "completed_runs": len(records),
            "outcomes": counts,
            "positive_rate": counts["positive"] / len(records) if records else 0.0,
            "positive_rate_wilson_95": _wilson(counts["positive"], len(records)),
            "disposition": disposition,
        }
        results.append(result)
        if stable_positive:
            qualified.append(result)
        incomplete = incomplete or not complete

    qualified.sort(key=lambda item: (item["gate_count"], item["enabled_gates"]))
    minimal_count = qualified[0]["gate_count"] if qualified else None
    minimal = [item for item in qualified if item["gate_count"] == minimal_count]

    qualified_sets = {tuple(item["enabled_gates"]) for item in qualified}
    monotonicity_violations = []
    for positive in qualified:
        positive_set = set(positive["enabled_gates"])
        for result in results:
            candidate_set = set(result["enabled_gates"])
            if positive_set < candidate_set and result["disposition"] == "not-stable-positive":
                monotonicity_violations.append(
                    {
                        "positive_subset": positive["candidate_id"],
                        "nonpositive_superset": result["candidate_id"],
                    }
                )

    one_minimal = []
    for item in qualified:
        enabled = set(item["enabled_gates"])
        if all(tuple(sorted(enabled - {gate})) not in qualified_sets for gate in enabled):
            one_minimal.append(item["candidate_id"])

    return {
        "schema_version": "rehostrace.schedule-search-result/v1",
        "search_id": manifest["search_id"],
        "status": "inconclusive" if incomplete else "passed",
        "manifest_sha256": validation["manifest_sha256"],
        "candidate_count": len(candidates),
        "trial_count": len(trials),
        "repetitions_per_candidate": repetitions,
        "results": results,
        "globally_minimal_gate_count": minimal_count,
        "globally_minimal_candidates": [item["candidate_id"] for item in minimal],
        "one_minimal_candidates": sorted(one_minimal),
        "monotonicity_violations": monotonicity_violations,
        "claim_boundary": manifest["claim_boundary"],
    }

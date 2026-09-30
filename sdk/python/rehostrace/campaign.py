"""Fail-closed aggregation for repeated oracle experiments."""

from __future__ import annotations

import math
from collections import Counter

from .model import ID_RE, SHA256_RE, canonical_sha256


VERDICTS = ("positive", "negative", "inconclusive")


def _canonical_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(f"{label} must be a canonical identifier")
    return value


def _unique_ids(value: object, label: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ValueError(f"{label} must be a {'possibly empty ' if allow_empty else ''}list")
    result = [_canonical_id(item, label) for item in value]
    if len(result) != len(set(result)):
        raise ValueError(f"{label} must contain unique identifiers")
    return result


def _percentile(values: list[int], fraction: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def _distribution(values: list[int]) -> dict:
    return {
        "observed": len(values),
        "minimum": min(values) if values else None,
        "median": _percentile(values, 0.5),
        "p95": _percentile(values, 0.95),
        "maximum": max(values) if values else None,
    }


def wilson_interval(successes: int, trials: int) -> list[float]:
    """Return the two-sided Wilson 95% binomial confidence interval."""

    if type(successes) is not int or type(trials) is not int:
        raise ValueError("Wilson counts must be integers")
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError("invalid Wilson counts")
    if trials == 0:
        return [0.0, 0.0]
    z = 1.959963984540054
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    center = (proportion + z * z / (2.0 * trials)) / denominator
    radius = z * math.sqrt(
        proportion * (1.0 - proportion) / trials
        + z * z / (4.0 * trials * trials)
    ) / denominator
    return [max(0.0, center - radius), min(1.0, center + radius)]


def validate_oracle_campaign_policy(policy: dict) -> dict:
    """Validate the contract for a repeated oracle campaign."""

    if (
        not isinstance(policy, dict)
        or policy.get("schema_version") != "rehostrace.oracle-campaign/v1"
    ):
        raise ValueError("invalid oracle-campaign schema_version")
    campaign_id = _canonical_id(policy.get("campaign_id"), "campaign_id")
    oracle_id = _canonical_id(policy.get("oracle_id"), "oracle_id")
    expected = policy.get("expected_runs")
    minimum = policy.get("minimum_positive_runs")
    if type(expected) is not int or not 1 <= expected <= 1_000_000:
        raise ValueError("expected_runs must be between 1 and 1000000")
    if type(minimum) is not int or not 0 <= minimum <= expected:
        raise ValueError("minimum_positive_runs must be within expected_runs")
    artifacts = _unique_ids(
        policy.get("required_artifacts"), "required_artifacts", allow_empty=False
    )
    tags = _unique_ids(policy.get("allowed_tags", []), "allowed_tags", allow_empty=True)
    effort_metric = policy.get("effort_metric")
    if effort_metric is not None:
        effort_metric = _canonical_id(effort_metric, "effort_metric")
    claim_boundary = policy.get("claim_boundary")
    if not isinstance(claim_boundary, str) or not claim_boundary:
        raise ValueError("claim_boundary must be non-empty text")
    return {
        "status": "passed",
        "campaign_id": campaign_id,
        "oracle_id": oracle_id,
        "expected_runs": expected,
        "minimum_positive_runs": minimum,
        "required_artifacts": artifacts,
        "allowed_tags": tags,
        "effort_metric": effort_metric,
        "policy_sha256": canonical_sha256(policy),
    }


def _validate_trial(policy: dict, trial: object, position: int) -> dict:
    if not isinstance(trial, dict):
        raise ValueError(f"trials[{position}] must be an object")
    run_id = _canonical_id(trial.get("run_id"), f"trials[{position}].run_id")
    result = trial.get("oracle_result")
    if not isinstance(result, dict):
        raise ValueError(f"trials[{position}].oracle_result must be an object")
    if result.get("oracle_id") != policy["oracle_id"]:
        raise ValueError(f"trial oracle differs from campaign policy: {run_id}")
    verdict = result.get("verdict")
    if verdict not in VERDICTS:
        raise ValueError(f"invalid oracle verdict: {run_id}")
    checks = result.get("checks")
    if (
        not isinstance(checks, dict)
        or not checks
        or any(not isinstance(name, str) or type(value) is not bool for name, value in checks.items())
    ):
        raise ValueError(f"trial checks must be a non-empty boolean object: {run_id}")
    if verdict == "positive" and not all(checks.values()):
        raise ValueError(f"positive trial contains a failed check: {run_id}")
    if verdict != "positive" and all(checks.values()):
        raise ValueError(f"non-positive trial has no failed check: {run_id}")

    artifacts = trial.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError(f"trial artifacts must be an object: {run_id}")
    identity = []
    for name in policy["required_artifacts"]:
        digest = artifacts.get(name)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError(f"invalid required artifact digest: {run_id}.{name}")
        identity.append((name, digest))

    tags = _unique_ids(trial.get("tags", []), f"trials[{position}].tags", allow_empty=True)
    unknown_tags = set(tags) - set(policy["allowed_tags"])
    if unknown_tags:
        raise ValueError(f"trial contains undeclared tags: {run_id}")

    effort = trial.get("effort")
    if policy["effort_metric"] is None:
        if effort is not None:
            raise ValueError(f"trial effort has no declared metric: {run_id}")
    elif type(effort) is not int or effort < 0:
        raise ValueError(f"trial effort must be a non-negative integer: {run_id}")

    receipt = trial.get("receipt_content_sha256")
    if receipt is not None and (
        not isinstance(receipt, str) or not SHA256_RE.fullmatch(receipt)
    ):
        raise ValueError(f"invalid receipt digest: {run_id}")
    return {
        "run_id": run_id,
        "verdict": verdict,
        "artifact_identity": tuple(identity),
        "tags": tags,
        "effort": effort,
    }


def summarize_oracle_campaign(policy: dict, trials: list[dict]) -> dict:
    """Aggregate repeated oracle results without collapsing inconclusive runs.

    A campaign passes only when every expected run is present, all required
    artifact identities are constant, and the declared minimum positive count
    is met.  Artifact drift is a hard failure.  Missing runs or an unmet
    positive threshold are inconclusive.
    """

    validation = validate_oracle_campaign_policy(policy)
    if not isinstance(trials, list):
        raise ValueError("trials must be a list")
    if len(trials) > validation["expected_runs"]:
        raise ValueError("trial count exceeds expected_runs")

    rows = [_validate_trial(validation, trial, index) for index, trial in enumerate(trials)]
    run_ids = [row["run_id"] for row in rows]
    if len(run_ids) != len(set(run_ids)):
        raise ValueError("campaign run ids must be unique")

    counts = {verdict: sum(row["verdict"] == verdict for row in rows) for verdict in VERDICTS}
    identities = {row["artifact_identity"] for row in rows}
    tag_counts = Counter(tag for row in rows for tag in row["tags"])
    efforts = [row["effort"] for row in rows if row["effort"] is not None]
    positive_efforts = [
        row["effort"]
        for row in rows
        if row["verdict"] == "positive" and row["effort"] is not None
    ]
    checks = {
        "expected_runs_observed": len(rows) == validation["expected_runs"],
        "artifact_identity_constant": len(identities) <= 1,
        "minimum_positive_runs_met": counts["positive"]
        >= validation["minimum_positive_runs"],
    }
    if not checks["artifact_identity_constant"]:
        status = "failed"
    elif not checks["expected_runs_observed"] or not checks["minimum_positive_runs_met"]:
        status = "inconclusive"
    else:
        status = "passed"

    total = len(rows)
    return {
        "schema_version": "rehostrace.oracle-campaign-result/v1",
        "campaign_id": validation["campaign_id"],
        "oracle_id": validation["oracle_id"],
        "status": status,
        "policy_sha256": validation["policy_sha256"],
        "expected_runs": validation["expected_runs"],
        "observed_runs": total,
        "checks": checks,
        "outcomes": counts,
        "positive_rate": counts["positive"] / total if total else 0.0,
        "positive_rate_wilson_95": wilson_interval(counts["positive"], total),
        "artifact_identity_variants": len(identities),
        "tag_counts": {tag: tag_counts[tag] for tag in validation["allowed_tags"]},
        "effort": {
            "metric": validation["effort_metric"],
            "all_runs": _distribution(efforts),
            "positive_runs": _distribution(positive_efforts),
        },
        "runs": [
            {
                "run_id": row["run_id"],
                "verdict": row["verdict"],
                "tags": row["tags"],
                "effort": row["effort"],
            }
            for row in rows
        ],
        "claim_boundary": policy["claim_boundary"],
    }

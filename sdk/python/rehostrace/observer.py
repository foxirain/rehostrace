"""Fail-closed observer-effect calibration with a held-out campaign pair.

The compiler learns one multiplicative rate correction from an observer-on /
observer-off training comparison and applies it to a separately identified
observer-on holdout campaign.  It deliberately records whether the evaluation
was retrospective and does not turn a QEMU rate into a stock-device claim.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from typing import Any

from .model import ID_RE, SHA256_RE


POLICY_SCHEMA = "rehostrace.observer-calibration-policy/v1"
RESULT_SCHEMA = "rehostrace.observer-calibration/v1"
MODEL = "multiplicative-relative-risk"


def _content_sha256(document: dict) -> str:
    material = copy.deepcopy(document)
    material.pop("integrity", None)
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_observer_calibration_policy(policy: dict) -> dict:
    if not isinstance(policy, dict) or policy.get("schema_version") != POLICY_SCHEMA:
        raise ValueError("invalid observer-calibration policy schema_version")
    calibration_id = policy.get("calibration_id")
    if not isinstance(calibration_id, str) or not ID_RE.fullmatch(calibration_id):
        raise ValueError("invalid observer-calibration calibration_id")
    sources = policy.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("observer-calibration sources are required")
    for field in ("training_report_sha256", "holdout_report_sha256"):
        if not isinstance(sources.get(field), str) or not SHA256_RE.fullmatch(sources[field]):
            raise ValueError(f"invalid observer-calibration source digest: {field}")
    if sources["training_report_sha256"] == sources["holdout_report_sha256"]:
        raise ValueError("training and holdout reports must be distinct")

    design = policy.get("design")
    if not isinstance(design, dict) or design.get("model") != MODEL:
        raise ValueError(f"observer-calibration model must be {MODEL}")
    if type(design.get("retrospective")) is not bool:
        raise ValueError("design.retrospective must be boolean")
    if type(design.get("pre_registered")) is not bool:
        raise ValueError("design.pre_registered must be boolean")
    if design["retrospective"] == design["pre_registered"]:
        raise ValueError("design must declare exactly one of retrospective or pre_registered")
    for field in ("training_design", "holdout_design"):
        if not isinstance(design.get(field), str) or not design[field]:
            raise ValueError(f"design.{field} must be non-empty")
    z = design.get("confidence_z")
    if not isinstance(z, (int, float)) or isinstance(z, bool) or not 1.0 < z < 4.0:
        raise ValueError("design.confidence_z must be between 1 and 4")

    acceptance = policy.get("acceptance")
    if not isinstance(acceptance, dict):
        raise ValueError("observer-calibration acceptance policy is required")
    error = acceptance.get("max_absolute_error")
    if not isinstance(error, (int, float)) or isinstance(error, bool) or not 0 < error < 1:
        raise ValueError("acceptance.max_absolute_error must be between 0 and 1")
    for field in ("require_actual_within_interval", "require_disjoint_campaigns"):
        if type(acceptance.get(field)) is not bool:
            raise ValueError(f"acceptance.{field} must be boolean")
    if not isinstance(policy.get("claim_boundary"), str) or not policy["claim_boundary"]:
        raise ValueError("observer-calibration claim_boundary is required")
    return {
        "status": "passed",
        "calibration_id": calibration_id,
        "policy_sha256": _canonical_sha256(policy),
    }


def _validate_arm(arm: Any, label: str) -> dict:
    if not isinstance(arm, dict):
        raise ValueError(f"{label} must be an object")
    runs = arm.get("runs")
    violations = arm.get("violations")
    clean = arm.get("clean")
    rate = arm.get("rate")
    if type(runs) is not int or runs <= 0:
        raise ValueError(f"{label}.runs must be positive")
    if type(violations) is not int or not 0 <= violations <= runs:
        raise ValueError(f"{label}.violations is invalid")
    if type(clean) is not int or clean != runs - violations:
        raise ValueError(f"{label}.clean is inconsistent")
    if not isinstance(rate, (int, float)) or isinstance(rate, bool):
        raise ValueError(f"{label}.rate is invalid")
    if not math.isclose(rate, violations / runs, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError(f"{label}.rate is inconsistent")
    campaign = arm.get("campaign")
    if (
        not isinstance(campaign, dict)
        or not isinstance(campaign.get("sha256"), str)
        or not SHA256_RE.fullmatch(campaign["sha256"])
    ):
        raise ValueError(f"{label}.campaign digest is invalid")
    identity = arm.get("identity")
    if (
        not isinstance(identity, list)
        or not identity
        or any(not isinstance(item, str) or not SHA256_RE.fullmatch(item) for item in identity)
    ):
        raise ValueError(f"{label}.identity is invalid")
    checks = arm.get("checks")
    if not isinstance(checks, dict) or not checks or not all(value is True for value in checks.values()):
        raise ValueError(f"{label}.checks did not all pass")
    return {
        "runs": runs,
        "violations": violations,
        "clean": clean,
        "rate": float(rate),
        "campaign_sha256": campaign["sha256"],
        "identity": identity,
    }


def _validate_report(report: Any, label: str) -> tuple[dict, dict]:
    if not isinstance(report, dict) or report.get("status") != "passed":
        raise ValueError(f"{label} report did not pass")
    observed = _validate_arm(report.get("observed"), f"{label}.observed")
    unobserved = _validate_arm(report.get("unobserved"), f"{label}.unobserved")
    if observed["identity"] != unobserved["identity"]:
        raise ValueError(f"{label} report changes target identity between arms")
    if observed["campaign_sha256"] == unobserved["campaign_sha256"]:
        raise ValueError(f"{label} report reuses one campaign in both arms")
    return observed, unobserved


def compile_observer_calibration(
    policy: dict,
    training_report: dict,
    holdout_report: dict,
    *,
    training_report_sha256: str,
    holdout_report_sha256: str,
) -> dict:
    validation = validate_observer_calibration_policy(policy)
    for supplied, field in (
        (training_report_sha256, "training_report_sha256"),
        (holdout_report_sha256, "holdout_report_sha256"),
    ):
        if not isinstance(supplied, str) or not SHA256_RE.fullmatch(supplied):
            raise ValueError(f"invalid supplied source digest: {field}")
        if supplied != policy["sources"][field]:
            raise ValueError(f"observer-calibration source hash mismatch: {field}")

    train_on, train_off = _validate_report(training_report, "training")
    holdout_on, holdout_off = _validate_report(holdout_report, "holdout")
    identities = {
        tuple(train_on["identity"]),
        tuple(train_off["identity"]),
        tuple(holdout_on["identity"]),
        tuple(holdout_off["identity"]),
    }
    if len(identities) != 1:
        raise ValueError("training and holdout target identities differ")
    campaigns = [
        train_on["campaign_sha256"],
        train_off["campaign_sha256"],
        holdout_on["campaign_sha256"],
        holdout_off["campaign_sha256"],
    ]
    campaigns_disjoint = len(set(campaigns)) == len(campaigns)
    if policy["acceptance"]["require_disjoint_campaigns"] and not campaigns_disjoint:
        raise ValueError("training and holdout campaigns are not disjoint")
    if train_on["violations"] == 0 or train_off["violations"] == 0:
        raise ValueError("multiplicative calibration requires non-zero training counts")

    relative_risk = train_off["rate"] / train_on["rate"]
    log_rr_se = math.sqrt(
        1 / train_off["violations"]
        - 1 / train_off["runs"]
        + 1 / train_on["violations"]
        - 1 / train_on["runs"]
    )
    z = float(policy["design"]["confidence_z"])
    rr_low = math.exp(math.log(relative_risk) - z * log_rr_se)
    rr_high = math.exp(math.log(relative_risk) + z * log_rr_se)
    predicted = min(1.0, max(0.0, holdout_on["rate"] * relative_risk))
    interval = [
        min(1.0, max(0.0, holdout_on["rate"] * rr_low)),
        min(1.0, max(0.0, holdout_on["rate"] * rr_high)),
    ]
    actual = holdout_off["rate"]
    absolute_error = abs(predicted - actual)
    checks = {
        "source_hashes_match_policy": True,
        "target_identity_invariant": True,
        "campaigns_disjoint": campaigns_disjoint,
        "holdout_label_not_used_for_fit": True,
        "heldout_actual_within_calibration_interval": interval[0] <= actual <= interval[1],
        "absolute_error_within_policy": absolute_error
        <= policy["acceptance"]["max_absolute_error"],
    }
    required_checks = ["source_hashes_match_policy", "target_identity_invariant"]
    if policy["acceptance"]["require_disjoint_campaigns"]:
        required_checks.append("campaigns_disjoint")
    if policy["acceptance"]["require_actual_within_interval"]:
        required_checks.append("heldout_actual_within_calibration_interval")
    required_checks.extend(["holdout_label_not_used_for_fit", "absolute_error_within_policy"])
    status = "passed" if all(checks[name] for name in required_checks) else "failed"
    identity = next(iter(identities))
    result = {
        "schema_version": RESULT_SCHEMA,
        "calibration_id": policy["calibration_id"],
        "status": status,
        "sources": {
            "policy_sha256": validation["policy_sha256"],
            "training_report_sha256": training_report_sha256,
            "holdout_report_sha256": holdout_report_sha256,
            "campaign_receipt_sha256": campaigns,
            "target_identity_sha256": _canonical_sha256(list(identity)),
        },
        "design": copy.deepcopy(policy["design"]),
        "training": {
            "observer_on": {
                "runs": train_on["runs"],
                "violations": train_on["violations"],
                "rate": train_on["rate"],
            },
            "observer_off": {
                "runs": train_off["runs"],
                "violations": train_off["violations"],
                "rate": train_off["rate"],
            },
            "estimated_relative_risk": relative_risk,
            "log_relative_risk_standard_error": log_rr_se,
            "relative_risk_interval": [rr_low, rr_high],
        },
        "holdout": {
            "observer_on": {
                "runs": holdout_on["runs"],
                "violations": holdout_on["violations"],
                "rate": holdout_on["rate"],
            },
            "observer_off": {
                "runs": holdout_off["runs"],
                "violations": holdout_off["violations"],
                "rate": holdout_off["rate"],
            },
            "predicted_unobserved_rate": predicted,
            "calibration_interval": interval,
            "absolute_error": absolute_error,
        },
        "acceptance": copy.deepcopy(policy["acceptance"]),
        "checks": checks,
        "claim_boundary": policy["claim_boundary"],
    }
    result["integrity"] = {"content_sha256": _content_sha256(result)}
    validate_observer_calibration(result)
    return result


def validate_observer_calibration(result: dict) -> dict:
    if not isinstance(result, dict) or result.get("schema_version") != RESULT_SCHEMA:
        raise ValueError("invalid observer-calibration result schema_version")
    if not isinstance(result.get("calibration_id"), str) or not ID_RE.fullmatch(
        result["calibration_id"]
    ):
        raise ValueError("invalid observer-calibration result id")
    if result.get("status") not in {"passed", "failed"}:
        raise ValueError("invalid observer-calibration result status")
    expected = _content_sha256(result)
    if result.get("integrity", {}).get("content_sha256") != expected:
        raise ValueError("observer-calibration integrity hash mismatch")
    sources = result.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("observer-calibration result sources are required")
    for field in (
        "policy_sha256",
        "training_report_sha256",
        "holdout_report_sha256",
        "target_identity_sha256",
    ):
        if not isinstance(sources.get(field), str) or not SHA256_RE.fullmatch(sources[field]):
            raise ValueError(f"invalid observer-calibration result digest: {field}")
    campaigns = sources.get("campaign_receipt_sha256")
    if (
        not isinstance(campaigns, list)
        or len(campaigns) != 4
        or any(not isinstance(item, str) or not SHA256_RE.fullmatch(item) for item in campaigns)
    ):
        raise ValueError("observer-calibration result must bind four campaign digests")

    design = result.get("design")
    if not isinstance(design, dict) or design.get("model") != MODEL:
        raise ValueError("observer-calibration result model is invalid")
    if type(design.get("retrospective")) is not bool or type(design.get("pre_registered")) is not bool:
        raise ValueError("observer-calibration result design flags are invalid")
    if design["retrospective"] == design["pre_registered"]:
        raise ValueError("observer-calibration result design flags are inconsistent")
    z = design.get("confidence_z")
    if not isinstance(z, (int, float)) or isinstance(z, bool) or not 1.0 < z < 4.0:
        raise ValueError("observer-calibration result confidence_z is invalid")

    def summary_arm(value: Any, label: str) -> dict:
        if not isinstance(value, dict):
            raise ValueError(f"{label} must be an object")
        runs = value.get("runs")
        violations = value.get("violations")
        rate = value.get("rate")
        if type(runs) is not int or runs <= 0:
            raise ValueError(f"{label}.runs is invalid")
        if type(violations) is not int or not 0 <= violations <= runs:
            raise ValueError(f"{label}.violations is invalid")
        if not isinstance(rate, (int, float)) or isinstance(rate, bool) or not math.isclose(
            rate, violations / runs, rel_tol=0.0, abs_tol=1e-12
        ):
            raise ValueError(f"{label}.rate is inconsistent")
        return {"runs": runs, "violations": violations, "rate": float(rate)}

    training = result.get("training")
    holdout = result.get("holdout")
    if not isinstance(training, dict) or not isinstance(holdout, dict):
        raise ValueError("observer-calibration result training and holdout are required")
    train_on = summary_arm(training.get("observer_on"), "training.observer_on")
    train_off = summary_arm(training.get("observer_off"), "training.observer_off")
    holdout_on = summary_arm(holdout.get("observer_on"), "holdout.observer_on")
    holdout_off = summary_arm(holdout.get("observer_off"), "holdout.observer_off")
    if train_on["violations"] == 0 or train_off["violations"] == 0:
        raise ValueError("observer-calibration result has zero training count")
    relative_risk = train_off["rate"] / train_on["rate"]
    log_rr_se = math.sqrt(
        1 / train_off["violations"]
        - 1 / train_off["runs"]
        + 1 / train_on["violations"]
        - 1 / train_on["runs"]
    )
    rr_interval = [
        math.exp(math.log(relative_risk) - float(z) * log_rr_se),
        math.exp(math.log(relative_risk) + float(z) * log_rr_se),
    ]
    predicted = min(1.0, max(0.0, holdout_on["rate"] * relative_risk))
    interval = [
        min(1.0, max(0.0, holdout_on["rate"] * rr_interval[0])),
        min(1.0, max(0.0, holdout_on["rate"] * rr_interval[1])),
    ]
    absolute_error = abs(predicted - holdout_off["rate"])

    def require_close(actual: Any, expected: float, label: str) -> None:
        if not isinstance(actual, (int, float)) or isinstance(actual, bool) or not math.isclose(
            float(actual), expected, rel_tol=1e-12, abs_tol=1e-12
        ):
            raise ValueError(f"observer-calibration derived value mismatch: {label}")

    require_close(training.get("estimated_relative_risk"), relative_risk, "relative_risk")
    require_close(
        training.get("log_relative_risk_standard_error"), log_rr_se, "log_relative_risk_se"
    )
    for index, expected_value in enumerate(rr_interval):
        try:
            actual_value = training["relative_risk_interval"][index]
        except (KeyError, IndexError, TypeError) as error:
            raise ValueError("observer-calibration relative-risk interval is invalid") from error
        require_close(actual_value, expected_value, f"relative_risk_interval[{index}]")
    require_close(holdout.get("predicted_unobserved_rate"), predicted, "prediction")
    require_close(holdout.get("absolute_error"), absolute_error, "absolute_error")
    for index, expected_value in enumerate(interval):
        try:
            actual_value = holdout["calibration_interval"][index]
        except (KeyError, IndexError, TypeError) as error:
            raise ValueError("observer-calibration interval is invalid") from error
        require_close(actual_value, expected_value, f"calibration_interval[{index}]")

    acceptance = result.get("acceptance")
    if not isinstance(acceptance, dict):
        raise ValueError("observer-calibration result acceptance is required")
    max_error = acceptance.get("max_absolute_error")
    if not isinstance(max_error, (int, float)) or isinstance(max_error, bool) or not 0 < max_error < 1:
        raise ValueError("observer-calibration result max_absolute_error is invalid")
    for field in ("require_actual_within_interval", "require_disjoint_campaigns"):
        if type(acceptance.get(field)) is not bool:
            raise ValueError(f"observer-calibration result acceptance flag is invalid: {field}")
    checks = result.get("checks")
    if not isinstance(checks, dict) or not checks or any(type(value) is not bool for value in checks.values()):
        raise ValueError("observer-calibration checks must be booleans")
    expected_checks = {
        "source_hashes_match_policy": True,
        "target_identity_invariant": True,
        "campaigns_disjoint": len(set(campaigns)) == 4,
        "holdout_label_not_used_for_fit": True,
        "heldout_actual_within_calibration_interval": interval[0]
        <= holdout_off["rate"]
        <= interval[1],
        "absolute_error_within_policy": absolute_error <= max_error,
    }
    if checks != expected_checks:
        raise ValueError("observer-calibration checks do not match recomputed values")
    required = [
        "source_hashes_match_policy",
        "target_identity_invariant",
        "holdout_label_not_used_for_fit",
        "absolute_error_within_policy",
    ]
    if acceptance["require_disjoint_campaigns"]:
        required.append("campaigns_disjoint")
    if acceptance["require_actual_within_interval"]:
        required.append("heldout_actual_within_calibration_interval")
    expected_status = "passed" if all(checks[name] for name in required) else "failed"
    if result["status"] != expected_status:
        raise ValueError("observer-calibration status differs from recomputed checks")
    if not isinstance(result.get("claim_boundary"), str) or not result["claim_boundary"]:
        raise ValueError("observer-calibration claim boundary is required")
    return {
        "status": result["status"],
        "calibration_id": result["calibration_id"],
        "content_sha256": expected,
    }

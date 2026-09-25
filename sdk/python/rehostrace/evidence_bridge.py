"""Generic causal-to-lifetime evidence-transfer bridge.

The bridge connects a named concurrent pair in a canonical trace to existing
portable execution and campaign receipts.  It does not infer product
reachability or scheduling from the receipts; every transferred claim and
every required oracle/fidelity property is declared in a policy.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from .model import CausalTrace, ID_RE, SHA256_RE
from .receipt import CLAIM_CLASSES, validate_receipt


POLICY_SCHEMA = "rehostrace.evidence-transfer-policy/v1"
BRIDGE_SCHEMA = "rehostrace.evidence-transfer-bridge/v1"


def _content_sha256(document: dict) -> str:
    material = copy.deepcopy(document)
    material.pop("integrity", None)
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _canonical_document_sha256(document: dict) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _string_list(value: Any, label: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ValueError(f"{label} must be a{' non-empty' if nonempty else ''} list")
    if any(not isinstance(item, str) or not item for item in value) or len(value) != len(
        set(value)
    ):
        raise ValueError(f"{label} must contain unique non-empty strings")
    return value


def _validate_transfer(transfer: Any) -> None:
    if not isinstance(transfer, dict):
        raise ValueError("evidence-transfer policy is required")
    allowed = _string_list(transfer.get("allowed_claims"), "allowed_claims", nonempty=True)
    forbidden = _string_list(
        transfer.get("forbidden_claims"), "forbidden_claims", nonempty=True
    )
    asserted = _string_list(
        transfer.get("asserted_claims"), "asserted_claims", nonempty=True
    )
    for label, claims in (
        ("allowed", allowed),
        ("forbidden", forbidden),
        ("asserted", asserted),
    ):
        unknown = set(claims) - CLAIM_CLASSES
        if unknown:
            raise ValueError(f"{label} claims are not registered: {sorted(unknown)}")
    if set(allowed) & set(forbidden):
        raise ValueError("allowed and forbidden bridge claims overlap")
    if set(asserted) - set(allowed):
        raise ValueError("asserted bridge claims are not allowed")


def validate_evidence_transfer_policy(policy: dict, trace: CausalTrace | None = None) -> dict:
    if not isinstance(policy, dict) or policy.get("schema_version") != POLICY_SCHEMA:
        raise ValueError("invalid evidence-transfer policy schema_version")
    bridge_id = policy.get("bridge_id")
    if not isinstance(bridge_id, str) or not ID_RE.fullmatch(bridge_id):
        raise ValueError("invalid evidence-transfer bridge_id")
    trace_sha = policy.get("trace_sha256")
    if not isinstance(trace_sha, str) or not SHA256_RE.fullmatch(trace_sha):
        raise ValueError("invalid evidence-transfer trace_sha256")
    pair = policy.get("pair")
    if not isinstance(pair, list) or len(pair) != 2:
        raise ValueError("evidence-transfer policy requires exactly two events")
    roles: set[str] = set()
    event_ids: list[str] = []
    for index, record in enumerate(pair):
        if not isinstance(record, dict):
            raise ValueError(f"evidence-transfer pair[{index}] must be an object")
        role = record.get("role")
        event_id = record.get("event_id")
        operation = record.get("operation")
        if not isinstance(role, str) or not ID_RE.fullmatch(role) or role in roles:
            raise ValueError("evidence-transfer pair roles must be unique canonical ids")
        if not isinstance(event_id, str) or not ID_RE.fullmatch(event_id):
            raise ValueError("evidence-transfer event ids must be canonical")
        if not isinstance(operation, str) or not operation:
            raise ValueError("evidence-transfer operations must be non-empty")
        roles.add(role)
        event_ids.append(event_id)
    if len(set(event_ids)) != 2:
        raise ValueError("evidence-transfer event ids must be unique")

    requirements = policy.get("requirements")
    if not isinstance(requirements, dict):
        raise ValueError("evidence-transfer requirements are required")
    single = requirements.get("single_receipt")
    campaign = requirements.get("campaign")
    if not isinstance(single, dict) or not isinstance(campaign, dict):
        raise ValueError("single_receipt and campaign requirements are required")
    _string_list(single.get("required_oracle_checks"), "single required_oracle_checks", nonempty=True)
    dimensions = single.get("required_fidelity_dimensions")
    if not isinstance(dimensions, dict) or not dimensions or any(
        not isinstance(key, str) or not isinstance(value, str) or not value
        for key, value in dimensions.items()
    ):
        raise ValueError("single required_fidelity_dimensions must be a non-empty object")
    if type(single.get("identity_token_count")) is not int or single["identity_token_count"] < 1:
        raise ValueError("single identity_token_count must be positive")
    for field in ("expected_runs", "expected_positive"):
        if type(campaign.get(field)) is not int or campaign[field] < 1:
            raise ValueError(f"campaign {field} must be positive")
    if campaign["expected_positive"] > campaign["expected_runs"]:
        raise ValueError("campaign expected_positive exceeds expected_runs")
    _string_list(
        campaign.get("required_oracle_checks"),
        "campaign required_oracle_checks",
        nonempty=True,
    )
    _validate_transfer(policy.get("transfer"))
    if not isinstance(policy.get("claim_boundary"), str) or not policy["claim_boundary"]:
        raise ValueError("evidence-transfer claim_boundary is required")

    pair_summary = None
    if trace is not None:
        if trace.digest != trace_sha:
            raise ValueError("evidence-transfer policy trace hash mismatch")
        for record in pair:
            event_id = record["event_id"]
            if event_id not in trace.events:
                raise ValueError(f"evidence-transfer event is absent: {event_id}")
            operation = trace.events[event_id]["boundary"]["operation"]
            if operation != record["operation"]:
                raise ValueError(f"evidence-transfer operation mismatch: {event_id}")
        if not trace.concurrent(event_ids[0], event_ids[1]):
            raise ValueError("evidence-transfer pair is causally ordered")
        subjects = {trace.events[event_id].get("subject") for event_id in event_ids}
        correlations = {
            trace.events[event_id].get("correlation", {}).get("session")
            for event_id in event_ids
        }
        if len(subjects) != 1 or None in subjects:
            raise ValueError("evidence-transfer pair does not share one subject")
        if len(correlations) != 1 or None in correlations:
            raise ValueError("evidence-transfer pair does not share one session correlation")
        pair_summary = {
            "relation": "concurrent",
            "shared_subject": True,
            "shared_session": True,
            "events": copy.deepcopy(pair),
        }
    return {
        "status": "passed",
        "bridge_id": bridge_id,
        "policy_sha256": _canonical_document_sha256(policy),
        "pair": pair_summary,
    }


def compile_evidence_transfer_bridge(
    policy: dict,
    trace: CausalTrace,
    single_receipt: dict,
    campaign_receipt: dict,
    campaign_result: dict,
    *,
    campaign_result_sha256: str,
) -> dict:
    policy_validation = validate_evidence_transfer_policy(policy, trace)
    single_validation = validate_receipt(single_receipt)
    campaign_validation = validate_receipt(campaign_receipt)
    if not isinstance(campaign_result_sha256, str) or not SHA256_RE.fullmatch(
        campaign_result_sha256
    ):
        raise ValueError("campaign_result_sha256 is invalid")

    pair_ids = [record["event_id"] for record in policy["pair"]]
    execution = single_receipt.get("execution", {})
    if execution.get("causal_trace_sha256") != trace.digest:
        raise ValueError("single receipt is not bound to the policy trace")
    projected = execution.get("projected_events")
    if not isinstance(projected, list) or len(projected) != 2 or set(projected) != set(pair_ids):
        raise ValueError("single receipt does not project exactly the policy pair")

    single_requirements = policy["requirements"]["single_receipt"]
    single_checks = single_receipt.get("oracle", {}).get("checks", {})
    missing_single_checks = [
        name
        for name in single_requirements["required_oracle_checks"]
        if single_checks.get(name) is not True
    ]
    if missing_single_checks:
        raise ValueError(f"single receipt oracle requirements failed: {missing_single_checks}")
    tokens = single_receipt.get("oracle", {}).get("identity_tokens", [])
    if len(tokens) != single_requirements["identity_token_count"]:
        raise ValueError("single receipt object identity cardinality differs from policy")
    single_dimensions = single_receipt.get("fidelity", {}).get("dimensions", {})
    for dimension, expected in single_requirements["required_fidelity_dimensions"].items():
        if single_dimensions.get(dimension) != expected:
            raise ValueError(f"single receipt fidelity requirement failed: {dimension}")

    campaign_requirements = policy["requirements"]["campaign"]
    campaign_checks = campaign_receipt.get("oracle", {}).get("checks", {})
    missing_campaign_checks = [
        name
        for name in campaign_requirements["required_oracle_checks"]
        if campaign_checks.get(name) is not True
    ]
    if missing_campaign_checks:
        raise ValueError(f"campaign receipt requirements failed: {missing_campaign_checks}")
    campaign_execution = campaign_receipt.get("execution", {})
    expected_runs = campaign_requirements["expected_runs"]
    expected_positive = campaign_requirements["expected_positive"]
    if campaign_execution.get("repetitions") != expected_runs:
        raise ValueError("campaign receipt run count differs from policy")
    if campaign_execution.get("positive") != expected_positive:
        raise ValueError("campaign receipt positive count differs from policy")

    result_role = next(
        (item for item in campaign_receipt.get("inputs", []) if item.get("role") == "campaign-result"),
        None,
    )
    if result_role is None or result_role.get("sha256") != campaign_result_sha256:
        raise ValueError("campaign receipt is not hash-bound to the supplied campaign result")
    if campaign_result.get("campaign_id") != campaign_receipt.get("receipt_id"):
        raise ValueError("campaign result and receipt identities differ")
    if campaign_result.get("repetitions") != expected_runs:
        raise ValueError("campaign result run count differs from policy")
    if campaign_result.get("positive") != expected_positive:
        raise ValueError("campaign result positive count differs from policy")
    if campaign_result.get("negative") != expected_runs - expected_positive:
        raise ValueError("campaign result negative count differs from policy")
    if campaign_result.get("inconclusive") != 0:
        raise ValueError("campaign result contains inconclusive trials")
    if not isinstance(campaign_result.get("checks"), dict) or not all(
        campaign_result["checks"].values()
    ):
        raise ValueError("campaign result checks did not all pass")

    transfer = policy["transfer"]
    single_transfer = single_receipt.get("fidelity", {}).get("transfer", {})
    campaign_transfer = campaign_receipt.get("fidelity", {}).get("transfer", {})
    asserted = set(transfer["asserted_claims"])
    if asserted - set(single_transfer.get("allowed_claims", [])):
        raise ValueError("bridge asserts claims not allowed by the single receipt")
    if "artifact.reproducibility" in asserted and "artifact.reproducibility" not in set(
        campaign_transfer.get("allowed_claims", [])
    ):
        raise ValueError("campaign receipt does not allow reproducibility transfer")
    required_forbidden = set(transfer["forbidden_claims"])
    if required_forbidden - set(single_transfer.get("forbidden_claims", [])):
        raise ValueError("single receipt does not preserve all bridge forbidden claims")
    if required_forbidden - set(campaign_transfer.get("forbidden_claims", [])):
        raise ValueError("campaign receipt does not preserve all bridge forbidden claims")

    bridge = {
        "schema_version": BRIDGE_SCHEMA,
        "bridge_id": policy["bridge_id"],
        "status": "passed",
        "sources": {
            "policy_sha256": policy_validation["policy_sha256"],
            "trace_id": trace.document["trace_id"],
            "trace_sha256": trace.digest,
            "single_receipt_id": single_receipt["receipt_id"],
            "single_receipt_sha256": single_validation["content_sha256"],
            "campaign_receipt_id": campaign_receipt["receipt_id"],
            "campaign_receipt_sha256": campaign_validation["content_sha256"],
            "campaign_result_sha256": campaign_result_sha256,
        },
        "causal_pair": policy_validation["pair"],
        "lifetime_evidence": {
            "object_identity_token_count": len(tokens),
            "object_identity_tokens_disclosed": False,
            "required_single_checks": len(single_requirements["required_oracle_checks"]),
            "verified_runs": expected_runs,
            "positive_runs": expected_positive,
            "negative_runs": expected_runs - expected_positive,
            "inconclusive_runs": 0,
            "campaign_trial_receipts_rehashed": campaign_checks.get(
                "all_trial_receipts_rehashed"
            )
            is True,
        },
        "transfer": copy.deepcopy(transfer),
        "claim_boundary": policy["claim_boundary"],
    }
    bridge["integrity"] = {"content_sha256": _content_sha256(bridge)}
    validate_evidence_transfer_bridge(bridge)
    return bridge


def validate_evidence_transfer_bridge(bridge: dict) -> dict:
    if not isinstance(bridge, dict) or bridge.get("schema_version") != BRIDGE_SCHEMA:
        raise ValueError("invalid evidence-transfer bridge schema_version")
    if bridge.get("status") != "passed":
        raise ValueError("evidence-transfer bridge is not passed")
    if not isinstance(bridge.get("bridge_id"), str) or not ID_RE.fullmatch(
        bridge["bridge_id"]
    ):
        raise ValueError("invalid evidence-transfer bridge id")
    sources = bridge.get("sources")
    required_digests = (
        "policy_sha256",
        "trace_sha256",
        "single_receipt_sha256",
        "campaign_receipt_sha256",
        "campaign_result_sha256",
    )
    if not isinstance(sources, dict) or any(
        not isinstance(sources.get(name), str) or not SHA256_RE.fullmatch(sources[name])
        for name in required_digests
    ):
        raise ValueError("evidence-transfer bridge source identities are invalid")
    pair = bridge.get("causal_pair")
    if (
        not isinstance(pair, dict)
        or pair.get("relation") != "concurrent"
        or pair.get("shared_subject") is not True
        or pair.get("shared_session") is not True
        or not isinstance(pair.get("events"), list)
        or len(pair["events"]) != 2
    ):
        raise ValueError("evidence-transfer bridge causal pair is incomplete")
    evidence = bridge.get("lifetime_evidence")
    if (
        not isinstance(evidence, dict)
        or evidence.get("object_identity_token_count") != 1
        or evidence.get("object_identity_tokens_disclosed") is not False
        or evidence.get("verified_runs", 0) < 1
        or evidence.get("positive_runs") != evidence.get("verified_runs")
        or evidence.get("negative_runs") != 0
        or evidence.get("inconclusive_runs") != 0
        or evidence.get("campaign_trial_receipts_rehashed") is not True
    ):
        raise ValueError("evidence-transfer bridge lifetime evidence is incomplete")
    _validate_transfer(bridge.get("transfer"))
    if not isinstance(bridge.get("claim_boundary"), str) or not bridge["claim_boundary"]:
        raise ValueError("evidence-transfer bridge claim boundary is required")
    expected = _content_sha256(bridge)
    if bridge.get("integrity", {}).get("content_sha256") != expected:
        raise ValueError("evidence-transfer bridge integrity hash mismatch")
    return {
        "status": "passed",
        "bridge_id": bridge["bridge_id"],
        "content_sha256": expected,
        "verified_runs": evidence["verified_runs"],
    }

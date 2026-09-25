"""Portable, self-hashing evidence receipts with explicit claim boundaries."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from pathlib import Path

from .model import ID_RE, SHA256_RE


FIDELITY_STATES = {
    "demonstrated",
    "modeled",
    "clean-control",
    "not-observed",
    "unavailable",
    "not-run",
    "not-applicable",
}

CLAIM_CLASSES = {
    "artifact.reproducibility",
    "mechanism.causal-replay",
    "mechanism.causal-projection",
    "mechanism.schedule-compilation",
    "mechanism.schedule-synthesis",
    "mechanism.schedule-search",
    "mechanism.schedule-enforcement",
    "finding.same-object-lifetime",
    "target.exact-binary-path",
    "target.vendor-vulnerability",
    "stock.remote-reachability",
    "stock.harmful-consequence",
    "stock.race-probability",
    "impact.exploitability",
    "impact.code-execution",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _content_sha256(receipt: dict) -> str:
    payload = copy.deepcopy(receipt)
    payload.pop("integrity", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def portable_path(path: Path, root: Path) -> str:
    resolved_path = path.resolve()
    resolved_root = root.resolve()
    try:
        return resolved_path.relative_to(resolved_root).as_posix()
    except ValueError as error:
        raise ValueError(f"artifact is outside receipt root: {resolved_path}") from error


def build_receipt(
    *,
    receipt_id: str,
    experiment: str,
    status: str,
    root: Path,
    inputs: list[dict],
    execution: dict,
    oracle: dict,
    fidelity: dict,
    claim_boundary: str,
) -> dict:
    bound_inputs = []
    for record in inputs:
        path = Path(record["path"])
        bound_inputs.append(
            {
                "role": record["role"],
                "path": portable_path(path, root),
                "sha256": sha256_file(path),
                "disclosure": record["disclosure"],
            }
        )
    receipt = {
        "schema_version": "rehostrace.evidence/v1",
        "receipt_id": receipt_id,
        "experiment": experiment,
        "status": status,
        "inputs": sorted(bound_inputs, key=lambda item: item["role"]),
        "execution": copy.deepcopy(execution),
        "oracle": {
            key: copy.deepcopy(oracle[key])
            for key in ("oracle_id", "verdict", "checks", "identity_tokens")
            if key in oracle
        },
        "fidelity": copy.deepcopy(fidelity),
        "claim_boundary": claim_boundary,
    }
    receipt["integrity"] = {"content_sha256": _content_sha256(receipt)}
    validate_receipt(receipt)
    return receipt


def validate_receipt(receipt: dict) -> dict:
    if not isinstance(receipt, dict) or receipt.get("schema_version") != "rehostrace.evidence/v1":
        raise ValueError("invalid receipt schema_version")
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not ID_RE.fullmatch(receipt_id):
        raise ValueError("invalid receipt_id")
    if receipt.get("status") not in {"passed", "failed", "inconclusive"}:
        raise ValueError("invalid receipt status")
    if not isinstance(receipt.get("experiment"), str) or not receipt["experiment"]:
        raise ValueError("experiment must be non-empty")
    roles: set[str] = set()
    for artifact in receipt.get("inputs", []):
        role = artifact.get("role") if isinstance(artifact, dict) else None
        if not isinstance(role, str) or not ID_RE.fullmatch(role) or role in roles:
            raise ValueError("receipt input roles must be unique canonical ids")
        roles.add(role)
        path = artifact.get("path")
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or os.path.isabs(path)
            or re.match(r"^[A-Za-z]:[\\/]", path)
        ):
            raise ValueError(f"receipt path must be portable and relative: {path!r}")
        if ".." in Path(path).parts:
            raise ValueError(f"receipt path cannot escape its root: {path}")
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError(f"invalid artifact digest: {role}")
        if artifact.get("disclosure") not in {"public", "private-hash-only", "vendor-approved"}:
            raise ValueError(f"invalid disclosure: {role}")
    if not roles:
        raise ValueError("receipt must bind at least one input")
    execution = receipt.get("execution")
    if not isinstance(execution, dict) or not isinstance(execution.get("event_order"), list):
        raise ValueError("invalid execution receipt")
    if not isinstance(execution.get("architecture"), str) or not execution["architecture"]:
        raise ValueError("execution.architecture must be non-empty")
    if not isinstance(execution.get("executor"), str) or not execution["executor"]:
        raise ValueError("execution.executor must be non-empty")
    if any(not isinstance(event, str) or not ID_RE.fullmatch(event) for event in execution["event_order"]):
        raise ValueError("execution.event_order must contain canonical ids")
    oracle = receipt.get("oracle")
    if not isinstance(oracle, dict) or oracle.get("verdict") not in {
        "positive",
        "negative",
        "inconclusive",
    }:
        raise ValueError("invalid oracle receipt")
    if not isinstance(oracle.get("oracle_id"), str) or not ID_RE.fullmatch(oracle["oracle_id"]):
        raise ValueError("invalid oracle id in receipt")
    if not isinstance(oracle.get("checks"), dict) or not all(
        type(value) is bool for value in oracle["checks"].values()
    ):
        raise ValueError("oracle checks must be booleans")
    if receipt["status"] == "passed" and (
        oracle["verdict"] != "positive" or not oracle["checks"] or not all(oracle["checks"].values())
    ):
        raise ValueError("a passed receipt requires a complete positive oracle")
    fidelity = receipt.get("fidelity")
    if not isinstance(fidelity, dict) or not isinstance(fidelity.get("dimensions"), dict):
        raise ValueError("invalid fidelity receipt")
    if not isinstance(fidelity.get("track"), str) or not ID_RE.fullmatch(fidelity["track"]):
        raise ValueError("invalid fidelity track")
    if not fidelity["dimensions"] or any(
        not isinstance(key, str) or not ID_RE.fullmatch(key) for key in fidelity["dimensions"]
    ):
        raise ValueError("fidelity dimensions must use canonical ids")
    if any(value not in FIDELITY_STATES for value in fidelity["dimensions"].values()):
        raise ValueError("invalid fidelity state")
    transfer = fidelity.get("transfer")
    if (
        not isinstance(transfer, dict)
        or not isinstance(transfer.get("allowed_claims"), list)
        or not isinstance(transfer.get("forbidden_claims"), list)
        or not isinstance(transfer.get("asserted_claims"), list)
    ):
        raise ValueError("fidelity transfer policy is required")
    allowed = transfer["allowed_claims"]
    forbidden = transfer["forbidden_claims"]
    asserted = transfer["asserted_claims"]
    for label, claims in (("allowed", allowed), ("forbidden", forbidden), ("asserted", asserted)):
        if any(not isinstance(claim, str) or claim not in CLAIM_CLASSES for claim in claims):
            raise ValueError(f"{label} claims must be unique registered claim classes")
        if len(claims) != len(set(claims)):
            raise ValueError(f"{label} claims must be unique registered claim classes")
    if set(allowed) & set(forbidden):
        raise ValueError("allowed and forbidden claims must be disjoint")
    invalid_assertions = set(asserted) - set(allowed)
    if invalid_assertions:
        raise ValueError(f"asserted claims are not allowed: {sorted(invalid_assertions)}")
    if not isinstance(receipt.get("claim_boundary"), str) or not receipt["claim_boundary"]:
        raise ValueError("claim_boundary must be non-empty")
    expected = _content_sha256(receipt)
    integrity = receipt.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("content_sha256") != expected:
        raise ValueError("receipt integrity hash mismatch")
    return {
        "status": "passed",
        "receipt_id": receipt_id,
        "content_sha256": expected,
        "input_count": len(roles),
    }


def verify_receipt_artifacts(receipt: dict, root: Path, *, require_private: bool = False) -> dict:
    """Validate a receipt and re-hash every locally required input."""

    validation = validate_receipt(receipt)
    resolved_root = root.resolve()
    verified: list[str] = []
    missing_private: list[str] = []
    for artifact in receipt["inputs"]:
        path = (resolved_root / artifact["path"]).resolve()
        try:
            path.relative_to(resolved_root)
        except ValueError as error:
            raise ValueError(f"receipt artifact escapes its root: {artifact['role']}") from error
        if not path.is_file():
            if artifact["disclosure"] == "private-hash-only" and not require_private:
                missing_private.append(artifact["role"])
                continue
            raise ValueError(f"receipt artifact is missing: {artifact['role']} ({artifact['path']})")
        actual = sha256_file(path)
        if actual != artifact["sha256"]:
            raise ValueError(
                f"receipt artifact hash mismatch: {artifact['role']} "
                f"expected={artifact['sha256']} actual={actual}"
            )
        verified.append(artifact["role"])
    return {
        **validation,
        "artifact_status": "passed" if not missing_private else "partial-private",
        "verified_roles": sorted(verified),
        "missing_private_roles": sorted(missing_private),
    }

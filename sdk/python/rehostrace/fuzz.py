"""Deterministic, offline coverage-guided fuzzing contracts.

The engine accepts an in-process callable.  It never opens a socket, launches
an external program, or treats policy data as executable code.  Integrators
may provide a parser harness whose outcome exposes stable semantic feature
tokens and one of four terminal states.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Iterable


STATUSES = {"ok", "reject", "crash", "hang"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(document: dict) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return _sha256(encoded)


@dataclass(frozen=True)
class FuzzOutcome:
    status: str
    features: frozenset[str]
    detail: str = ""

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unsupported fuzz outcome status: {self.status}")
        if any(not isinstance(item, str) or not item for item in self.features):
            raise ValueError("fuzz outcome features must be non-empty strings")


def validate_fuzz_policy(document: dict) -> dict:
    if document.get("schema_version") != "rehostrace.fuzz-policy/v1":
        raise ValueError("unsupported fuzz policy schema")
    campaign_id = document.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id:
        raise ValueError("fuzz policy requires a campaign_id")
    limits = document.get("limits")
    if not isinstance(limits, dict):
        raise ValueError("fuzz policy requires limits")
    executions = limits.get("executions")
    max_input_bytes = limits.get("max_input_bytes")
    if type(executions) is not int or not 1 <= executions <= 1_000_000:
        raise ValueError("executions must be in 1..1000000")
    if type(max_input_bytes) is not int or not 1 <= max_input_bytes <= 1_048_576:
        raise ValueError("max_input_bytes must be in 1..1048576")
    dictionary = document.get("dictionary_hex", [])
    if not isinstance(dictionary, list) or len(dictionary) > 1024:
        raise ValueError("dictionary_hex must be a bounded list")
    decoded: list[bytes] = []
    for item in dictionary:
        if not isinstance(item, str) or len(item) % 2:
            raise ValueError("dictionary entries must be whole hexadecimal bytes")
        try:
            token = bytes.fromhex(item)
        except ValueError as error:
            raise ValueError("dictionary entries must be hexadecimal") from error
        if not token or len(token) > max_input_bytes:
            raise ValueError("dictionary entry length is invalid")
        decoded.append(token)
    seeds = document.get("seeds_hex")
    if not isinstance(seeds, list) or not seeds:
        raise ValueError("fuzz policy requires at least one seed")
    decoded_seeds: list[bytes] = []
    for item in seeds:
        if not isinstance(item, str) or len(item) % 2:
            raise ValueError("seed must contain whole hexadecimal bytes")
        try:
            seed = bytes.fromhex(item)
        except ValueError as error:
            raise ValueError("seed must be hexadecimal") from error
        if len(seed) > max_input_bytes:
            raise ValueError("seed exceeds max_input_bytes")
        decoded_seeds.append(seed)
    stop = document.get("stop_on", [])
    if not isinstance(stop, list) or len(stop) != len(set(stop)) or any(
        item not in {"crash", "hang"} for item in stop
    ):
        raise ValueError("stop_on may contain crash and hang once each")
    return {
        "campaign_id": campaign_id,
        "executions": executions,
        "max_input_bytes": max_input_bytes,
        "dictionary": decoded,
        "seeds": decoded_seeds,
        "stop_on": frozenset(stop),
        "policy_sha256": _canonical(document),
    }


class CoverageGuidedFuzzer:
    """Small deterministic queue fuzzer for reproducible parser experiments."""

    def __init__(self, policy: dict, target: Callable[[bytes], FuzzOutcome]):
        self.policy = validate_fuzz_policy(policy)
        self.target = target

    def _mutations(self, data: bytes) -> Iterable[tuple[str, bytes]]:
        limit = self.policy["max_input_bytes"]
        replacements = (0x00, 0x01, 0x7F, 0x80, 0xFF)
        for index in range(len(data)):
            for value in replacements:
                if data[index] != value:
                    yield f"replace:{index}:{value:02x}", data[:index] + bytes([value]) + data[index + 1 :]
            yield f"delete:{index}", data[:index] + data[index + 1 :]
        if len(data) < limit:
            for value in replacements:
                yield f"append:{value:02x}", data + bytes([value])
        for token_index, token in enumerate(self.policy["dictionary"]):
            if len(data) + len(token) <= limit:
                yield f"dictionary-append:{token_index}", data + token
            for offset in range(min(len(data), max(1, limit - len(token) + 1))):
                candidate = data[:offset] + token + data[offset + len(token) :]
                if len(candidate) <= limit:
                    yield f"dictionary-overlay:{token_index}:{offset}", candidate

    def run(self) -> dict:
        queue: list[tuple[bytes, str, str | None]] = []
        queued: set[str] = set()
        for seed in self.policy["seeds"]:
            digest = _sha256(seed)
            if digest not in queued:
                queue.append((seed, "seed", None))
                queued.add(digest)

        corpus: list[dict] = []
        findings: list[dict] = []
        global_features: set[str] = set()
        status_counts = {status: 0 for status in sorted(STATUSES)}
        executions = 0
        cursor = 0
        while queue and executions < self.policy["executions"]:
            parent, _, parent_digest = queue[cursor % len(queue)]
            candidates = [("identity", parent), *self._mutations(parent)]
            for mutation, candidate in candidates:
                if executions >= self.policy["executions"]:
                    break
                outcome = self.target(candidate)
                if not isinstance(outcome, FuzzOutcome):
                    raise TypeError("fuzz target must return FuzzOutcome")
                executions += 1
                status_counts[outcome.status] += 1
                digest = _sha256(candidate)
                new_features = sorted(outcome.features - global_features)
                if new_features:
                    global_features.update(new_features)
                    corpus.append(
                        {
                            "input_sha256": digest,
                            "length": len(candidate),
                            "parent_sha256": parent_digest,
                            "mutation": mutation,
                            "new_features": new_features,
                            "status": outcome.status,
                        }
                    )
                    if digest not in queued:
                        queue.append((candidate, mutation, digest))
                        queued.add(digest)
                if outcome.status in {"crash", "hang"}:
                    findings.append(
                        {
                            "kind": outcome.status,
                            "input_sha256": digest,
                            "length": len(candidate),
                            "detail": outcome.detail,
                            "features": sorted(outcome.features),
                        }
                    )
                    if outcome.status in self.policy["stop_on"]:
                        return self._report(executions, status_counts, global_features, corpus, findings)
            cursor += 1
            if cursor >= len(queue):
                break
        return self._report(executions, status_counts, global_features, corpus, findings)

    def _report(
        self,
        executions: int,
        status_counts: dict,
        features: set[str],
        corpus: list[dict],
        findings: list[dict],
    ) -> dict:
        report = {
            "schema_version": "rehostrace.fuzz-campaign/v1",
            "campaign_id": self.policy["campaign_id"],
            "policy_sha256": self.policy["policy_sha256"],
            "engine": "deterministic-coverage-queue/v1",
            "executions": executions,
            "status_counts": status_counts,
            "features": sorted(features),
            "corpus": corpus,
            "findings": findings,
        }
        report["report_sha256"] = _canonical(report)
        return report

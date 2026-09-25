#!/usr/bin/env python3
"""Replay every public Bluetooth profile without a target-specific projection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (  # noqa: E402
    BluetoothCoreAdapter,
    CausalTrace,
    ReplayEngine,
    build_receipt,
    default_bluetooth_registrations,
    validate_profile_catalog,
)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_catalog(document: dict, fixture_dir: Path) -> dict:
    validated = validate_profile_catalog(document)
    for profile in validated["profiles"]:
        for name in [profile["trace"], *profile["packs"]]:
            if not (fixture_dir / name).is_file():
                raise ValueError(f"profile {profile['id']} references a missing fixture: {name}")
    return validated


def run_profile(spec: dict, fixture_dir: Path, output: Path) -> dict:
    trace_path = fixture_dir / spec["trace"]
    pack_paths = [fixture_dir / name for name in spec["packs"]]
    trace = CausalTrace(read_json(trace_path))
    manifests = [read_json(path) for path in pack_paths]
    adapter = BluetoothCoreAdapter(default_bluetooth_registrations(manifests))
    replay = ReplayEngine(trace, adapter).run()
    summary = adapter.summary()
    checks = {
        "semantic_replay_passed": replay["status"] == "passed",
        "all_events_replayed": len(replay["event_order"]) == len(trace.events),
        "protocol_packs_bound": len(summary["protocol_packs"]) == len(pack_paths),
        "state_observations_emitted": summary["event_count"] == len(trace.events),
    }
    profile_output = output / spec["id"]
    write_json(profile_output / "trace-validation.json", trace.validation)
    write_json(profile_output / "replay.json", replay)
    write_json(profile_output / "state-summary.json", summary)
    return {
        "profile_id": spec["id"],
        "transport": spec["transport"],
        "state_machines": list(spec["state_machines"]),
        "trace": str(trace_path.relative_to(ROOT)),
        "trace_sha256": trace.digest,
        "protocol_packs": summary["protocol_packs"],
        "event_count": len(replay["event_order"]),
        "event_order": replay["event_order"],
        "checks": checks,
        "status": "passed" if all(checks.values()) else "failed",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out/bluetooth_profiles")
    parser.add_argument(
        "--catalog",
        type=Path,
        default=ROOT / "fixtures/bluetooth/profile_catalog.json",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    fixture_dir = ROOT / "fixtures/bluetooth"
    catalog = validate_catalog(read_json(args.catalog), fixture_dir)
    results = [run_profile(spec, fixture_dir, output) for spec in catalog["profiles"]]

    matrix = {
        "schema_version": "rehostrace.bluetooth-profile-matrix/v1",
        "status": "passed" if all(item["status"] == "passed" for item in results) else "failed",
        "profile_count": len(results),
        "transport_families": sorted({item["transport"] for item in results}),
        "profiles": [{key: value for key, value in item.items() if key != "event_order"} for item in results],
        "open_profiles": catalog["open_profiles"],
        "non_claims": [
            "complete Bluetooth implementation",
            "controller firmware or radio emulation",
            "operating-system framework fidelity",
            "stock-device reachability or consequence",
            "vulnerability or exploitability",
        ],
    }
    write_json(output / "profile-matrix.json", matrix)

    inputs = [
        {"role": "profile-runner", "path": Path(__file__), "disclosure": "public"},
        {"role": "profile-catalog", "path": args.catalog, "disclosure": "public"},
        {"role": "bluetooth-sdk", "path": ROOT / "sdk/python/rehostrace/bluetooth.py", "disclosure": "public"},
    ]
    seen: set[Path] = set()
    for spec in catalog["profiles"]:
        for path in [fixture_dir / spec["trace"], *(fixture_dir / name for name in spec["packs"])]:
            if path not in seen:
                inputs.append(
                    {"role": f"profile-input-{len(seen):02d}", "path": path, "disclosure": "public"}
                )
                seen.add(path)

    state_machines = {state for item in results for state in item["state_machines"]}
    checks = {
        "three_vertical_slices_passed": len(results) == 3
        and all(item["status"] == "passed" for item in results),
        "classic_and_le_covered": matrix["transport_families"] == ["BR/EDR ACL", "LE ACL"],
        "application_state_machines_covered": {"AVDTP", "SDP", "ATT", "GATT"}.issubset(state_machines),
    }
    status = "passed" if all(checks.values()) else "failed"
    receipt = build_receipt(
        receipt_id="public.bluetooth-profile-matrix.v1",
        experiment="Public causal Bluetooth profile breadth matrix",
        status=status,
        root=ROOT,
        inputs=inputs,
        execution={
            "architecture": "portable-model",
            "executor": "rehostrace-bluetooth-profile-matrix",
            "event_order": [
                f"{item['profile_id']}:{event_id}"
                for item in results
                for event_id in item["event_order"]
            ],
            "profiles": [
                {
                    "profile_id": item["profile_id"],
                    "trace_sha256": item["trace_sha256"],
                    "event_count": item["event_count"],
                }
                for item in results
            ],
        },
        oracle={
            "oracle_id": "public.bluetooth.profile-breadth.v1",
            "verdict": "positive" if status == "passed" else "negative",
            "checks": checks,
            "identity_tokens": [],
        },
        fidelity={
            "track": "public.synthetic.bluetooth-profile-matrix",
            "dimensions": {
                "explicit_causal_order": "demonstrated",
                "classic_hci_acl": "demonstrated",
                "le_hci_acl": "demonstrated",
                "avdtp_state": "demonstrated",
                "sdp_state": "demonstrated",
                "att_gatt_state": "demonstrated",
                "proprietary_binary": "not-run",
                "controller_firmware": "not-applicable",
                "radio_timing": "not-applicable",
            },
            "transfer": {
                "allowed_claims": ["artifact.reproducibility", "mechanism.causal-replay"],
                "forbidden_claims": [
                    "target.vendor-vulnerability",
                    "stock.remote-reachability",
                    "stock.harmful-consequence",
                    "impact.exploitability",
                ],
                "asserted_claims": ["artifact.reproducibility", "mechanism.causal-replay"],
            },
        },
        claim_boundary=(
            "This receipt demonstrates three public synthetic causal vertical slices across "
            "Classic and LE host boundaries. It is not a complete Bluetooth stack, controller "
            "or radio emulator, real-device result, vulnerability finding, or exploitability claim."
        ),
    )
    write_json(output / "evidence-receipt.json", receipt)
    print(
        json.dumps(
            {
                "status": status,
                "profiles": len(results),
                "open_profiles": len(catalog["open_profiles"]),
                "events": sum(item["event_count"] for item in results),
                "receipt_sha256": receipt["integrity"]["content_sha256"],
                "output": str(output),
            },
            sort_keys=True,
        )
    )
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

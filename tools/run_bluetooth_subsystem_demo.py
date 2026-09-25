#!/usr/bin/env python3
"""Replay the public HCI/ACL/L2CAP/AVDTP fixture and emit evidence."""

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
)


PACK_NAMES = (
    "hci_core.pack.json",
    "l2cap_core.pack.json",
    "avdtp_signaling.pack.json",
)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out/bluetooth_subsystem")
    args = parser.parse_args()
    output = args.output.resolve()

    trace_path = ROOT / "fixtures/bluetooth/hci_l2cap_avdtp.causal.json"
    pack_paths = [ROOT / "fixtures/bluetooth" / name for name in PACK_NAMES]
    trace = CausalTrace(read_json(trace_path))
    manifests = [read_json(path) for path in pack_paths]
    adapter = BluetoothCoreAdapter(default_bluetooth_registrations(manifests))
    replay = ReplayEngine(trace, adapter).run()
    summary = adapter.summary()

    checks = {
        "all_events_replayed": len(replay["event_order"]) == 31,
        "acl_link_closed": summary["connections"]["0x0040"]["state"] == "disconnected",
        "l2cap_channel_closed": summary["channels"]["0x0040/0x0040"]["state"] == "closed",
        "avdtp_response_matched": summary["avdtp_sessions"]["0x0040/0x0040"]["state"] == "discovered",
        "three_protocol_packs_bound": len(summary["protocol_packs"]) == 3,
    }
    oracle = {
        "oracle_id": "public.bluetooth.lifecycle.v1",
        "verdict": "positive" if all(checks.values()) else "negative",
        "checks": checks,
        "identity_tokens": [],
    }
    status = "passed" if oracle["verdict"] == "positive" else "failed"
    write_json(output / "trace-validation.json", trace.validation)
    write_json(output / "replay.json", replay)
    write_json(output / "state-summary.json", summary)

    inputs = [
        {"role": "causal-trace", "path": trace_path, "disclosure": "public"},
        {"role": "sdk-bluetooth", "path": ROOT / "sdk/python/rehostrace/bluetooth.py", "disclosure": "public"},
        {"role": "sdk-model", "path": ROOT / "sdk/python/rehostrace/model.py", "disclosure": "public"},
        {"role": "sdk-replay", "path": ROOT / "sdk/python/rehostrace/replay.py", "disclosure": "public"},
        {"role": "experiment-runner", "path": Path(__file__), "disclosure": "public"},
    ]
    for path in pack_paths:
        inputs.append(
            {"role": path.stem.replace("_", "-"), "path": path, "disclosure": "public"}
        )
    receipt = build_receipt(
        receipt_id="public.bluetooth-subsystem.v1",
        experiment="Public stateful HCI, ACL, L2CAP, and AVDTP causal replay",
        status=status,
        root=ROOT,
        inputs=inputs,
        execution={
            "architecture": "portable-model",
            "executor": "rehostrace-bluetooth-core",
            "event_order": replay["event_order"],
            "trace_sha256": trace.digest,
            "protocol_pack_sha256": summary["protocol_packs"],
        },
        oracle=oracle,
        fidelity={
            "track": "public.synthetic.bluetooth-model",
            "dimensions": {
                "explicit_causal_order": "demonstrated",
                "hci_command_and_link_state": "demonstrated",
                "acl_fragment_reassembly": "demonstrated",
                "l2cap_channel_lifecycle": "demonstrated",
                "avdtp_transaction_matching": "demonstrated",
                "exact_vendor_binary": "not-run",
                "controller_firmware": "not-applicable",
                "radio_timing": "not-applicable",
                "stock_harmful_consequence": "not-applicable"
            },
            "transfer": {
                "allowed_claims": [
                    "artifact.reproducibility",
                    "mechanism.causal-replay",
                    "mechanism.causal-projection"
                ],
                "forbidden_claims": [
                    "finding.same-object-lifetime",
                    "target.exact-binary-path",
                    "target.vendor-vulnerability",
                    "stock.remote-reachability",
                    "stock.harmful-consequence",
                    "stock.race-probability",
                    "impact.exploitability",
                    "impact.code-execution"
                ],
                "asserted_claims": [
                    "artifact.reproducibility",
                    "mechanism.causal-replay",
                    "mechanism.causal-projection"
                ]
            }
        },
        claim_boundary=(
            "This public synthetic receipt demonstrates stateful causal replay across HCI, ACL "
            "fragmentation, L2CAP channel setup/teardown, and AVDTP transaction matching. It does "
            "not claim controller or radio emulation, execution of a proprietary binary, stock "
            "device reachability, a real-device consequence, or exploitability."
        ),
    )
    write_json(output / "evidence-receipt.json", receipt)
    print(
        json.dumps(
            {
                "status": status,
                "events": len(replay["event_order"]),
                "protocol_packs": len(summary["protocol_packs"]),
                "trace_sha256": trace.digest,
                "receipt_sha256": receipt["integrity"]["content_sha256"],
                "output": str(output),
            },
            sort_keys=True,
        )
    )
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Compile a public boundary bundle and replay its HCI state offline."""

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
    compile_capture_bundle,
    default_bluetooth_registrations,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out/capture_replay")
    args = parser.parse_args()
    source = json.loads((ROOT / "fixtures/capture/public_bluetooth_capture.json").read_text())
    trace_document = compile_capture_bundle(source)
    trace = CausalTrace(trace_document)
    manifest = json.loads((ROOT / "fixtures/bluetooth/hci_core.pack.json").read_text())
    adapter = BluetoothCoreAdapter(default_bluetooth_registrations([manifest]))
    replay = ReplayEngine(trace, adapter).run()
    summary = adapter.summary()
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "compiled-trace.json").write_text(json.dumps(trace_document, indent=2, sort_keys=True) + "\n")
    (args.output / "replay.json").write_text(json.dumps(replay, indent=2, sort_keys=True) + "\n")
    (args.output / "state-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    result = {"status": replay["status"], "events": len(trace.events), "trace_sha256": trace.digest, "output": str(args.output)}
    print(json.dumps(result, sort_keys=True))
    return 0 if replay["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

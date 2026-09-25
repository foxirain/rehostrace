#!/usr/bin/env python3
"""Run the public Bluetooth expansion slices and issue one bounded receipt."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import build_receipt  # noqa: E402


def run(script: str, output: Path) -> dict:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools" / script), "--output", str(output)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"{script} emitted no result")
    return json.loads(lines[-1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "out/full_bluetooth_platform")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    profiles = run("run_bluetooth_profile_demo.py", output / "profiles")
    fuzz = run("run_public_fuzz_demo.py", output / "fuzz" / "campaign.json")
    parser_fuzz = run("run_bluetooth_parser_fuzz_demo.py", output / "parser-fuzz")
    capture = run("run_capture_replay_demo.py", output / "capture")
    analysis = run("run_analysis_pipeline_demo.py", output / "analysis")
    checks = {
        "seven_protocol_slices": profiles["status"] == "passed" and profiles["profiles"] == 7,
        "coverage_campaign_executed": fuzz["executions"] > 0 and fuzz["features"] > 0,
        "seeded_parser_oracle_retained": fuzz["findings"] == 1,
        "six_bluetooth_parser_campaigns": parser_fuzz["status"] == "passed"
        and parser_fuzz["campaigns"] == 6,
        "capture_compiled_and_replayed": capture["status"] == "passed",
        "cfg_lifetime_candidate_found": analysis["lifetime_candidates"] >= 1,
        "schedule_candidate_synthesized": analysis["schedules"] >= 1,
        "version_changes_reported": analysis["version_changes"] >= 1,
    }
    status = "passed" if all(checks.values()) else "failed"
    matrix = {
        "schema_version": "rehostrace.bluetooth-platform-capabilities/v1",
        "status": status,
        "capabilities": [
            {"id": "semantic-protocol-packs", "state": "executed-public-fixture", "result": profiles},
            {"id": "coverage-guided-fuzzing", "state": "executed-public-fixture", "result": fuzz},
            {"id": "bluetooth-parser-fuzzing", "state": "executed-public-fixture", "result": parser_fuzz},
            {"id": "capture-offline-replay", "state": "executed-public-fixture", "result": capture},
            {"id": "cfg-schedule-analysis", "state": "executed-public-fixture", "result": analysis},
            {"id": "android-native-stack", "state": "contract-only", "result": {"executed": False}},
            {"id": "controller-firmware", "state": "contract-only", "result": {"executed": False}}
        ],
        "checks": checks,
        "claim_boundary": "Public synthetic mechanisms only; native-stack, controller-firmware, physical-target reachability, vulnerability, and exploitability are not established."
    }
    (output / "capability-matrix.json").write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n")

    inputs = [
        ("platform-runner", "tools/run_full_bluetooth_platform_demo.py"),
        ("profile-catalog", "fixtures/bluetooth/profile_catalog.json"),
        ("fuzz-policy", "fixtures/fuzz/public_parser.policy.json"),
        ("parser-fuzz-policies", "fixtures/fuzz/bluetooth_parsers.campaigns.json"),
        ("capture-bundle", "fixtures/capture/public_bluetooth_capture.json"),
        ("binary-cfg", "fixtures/cfg/lock_handoff.graph.json"),
        ("target-v1", "fixtures/differential/target_v1.json"),
        ("target-v2", "fixtures/differential/target_v2.json"),
        ("native-plan", "fixtures/harness/android_native.plan.json"),
        ("controller-plan", "fixtures/harness/controller_firmware.plan.json"),
    ]
    receipt = build_receipt(
        receipt_id="public.bluetooth-platform.v2",
        experiment="Public Bluetooth research-platform expansion",
        status=status,
        root=ROOT,
        inputs=[{"role": role, "path": ROOT / path, "disclosure": "public"} for role, path in inputs],
        execution={
            "architecture": "portable-model",
            "executor": "rehostrace-bluetooth-platform-runner",
            "event_order": [
                "profiles.complete",
                "fuzz.complete",
                "parser-fuzz.complete",
                "capture.complete",
                "cfg.complete",
                "schedule.complete",
                "differential.complete",
            ],
            "capability_states": {item["id"]: item["state"] for item in matrix["capabilities"]},
        },
        oracle={
            "oracle_id": "public.bluetooth-platform.contracts.v2",
            "verdict": "positive" if status == "passed" else "negative",
            "checks": checks,
            "identity_tokens": [],
        },
        fidelity={
            "track": "public.synthetic.bluetooth-platform",
            "dimensions": {
                "semantic_protocol_lifecycle": "demonstrated",
                "offline_parser_fuzzing": "demonstrated",
                "capture_compilation": "demonstrated",
                "normalized_cfg_analysis": "demonstrated",
                "schedule_candidate_synthesis": "demonstrated",
                "version_differential": "demonstrated",
                "native_stack_execution": "not-run",
                "controller_firmware_execution": "not-run",
                "physical_target_observation": "not-run",
            },
            "transfer": {
                "allowed_claims": ["artifact.reproducibility", "mechanism.causal-replay", "mechanism.schedule-synthesis"],
                "forbidden_claims": ["finding.same-object-lifetime", "target.exact-binary-path", "target.vendor-vulnerability", "stock.remote-reachability", "stock.harmful-consequence", "stock.race-probability", "impact.exploitability", "impact.code-execution"],
                "asserted_claims": ["artifact.reproducibility", "mechanism.causal-replay", "mechanism.schedule-synthesis"],
            },
        },
        claim_boundary=matrix["claim_boundary"],
    )
    (output / "evidence-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": status, "checks": len(checks), "receipt_sha256": receipt["integrity"]["content_sha256"], "output": str(output)}, sort_keys=True))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

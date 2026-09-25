import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import analyze_lifetime_cfg, compare_target_manifests, compile_harness_plan, synthesize_lifetime_schedules, validate_binary_cfg  # noqa: E402


def read(path):
    return json.loads(path.read_text())


class AnalysisPipelineTests(unittest.TestCase):
    def test_cfg_discovers_and_synthesizes_structural_candidate(self):
        analysis = analyze_lifetime_cfg(read(ROOT / "fixtures/cfg/lock_handoff.graph.json"))
        self.assertEqual(analysis["candidate_count"], 1)
        self.assertTrue(analysis["candidates"][0]["handoffs"])
        schedules = synthesize_lifetime_schedules(analysis)
        self.assertEqual(len(schedules["schedules"]), 1)
        self.assertTrue(schedules["schedules"][0]["oracle"]["require_same_identity"])

    def test_cfg_rejects_unbalanced_lock_model(self):
        graph = read(ROOT / "fixtures/cfg/lock_handoff.graph.json")
        graph["nodes"][0]["operations"].pop()
        with self.assertRaisesRegex(ValueError, "held locks"):
            validate_binary_cfg(graph)

    def test_version_diff_tracks_binary_abi_and_fact_changes(self):
        report = compare_target_manifests(read(ROOT / "fixtures/differential/target_v1.json"), read(ROOT / "fixtures/differential/target_v2.json"))
        changed = next(item for item in report["changes"] if item["component_id"] == "host.driver")
        self.assertTrue(changed["binary_changed"])
        self.assertTrue(changed["abi_changed"])
        self.assertIn("lifetime_candidates", changed["fact_changes"])

    def test_harness_contracts_are_hash_pinned_and_not_claimed_executable(self):
        for name in ("android_native.plan.json", "controller_firmware.plan.json"):
            execution = compile_harness_plan(read(ROOT / "fixtures/harness" / name))
            self.assertFalse(execution["executable"])
            self.assertEqual(len(execution["identity"]["target_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()

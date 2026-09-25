import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (  # noqa: E402
    analyze_lifetime_cfg,
    compile_target_controller,
    render_target_controller_header,
    synthesize_lifetime_schedules,
    validate_target_lowering,
)


def read(path):
    return json.loads(path.read_text())


class TargetLoweringTests(unittest.TestCase):
    def inputs(self):
        analysis = analyze_lifetime_cfg(read(ROOT / "fixtures/cfg/lock_handoff.graph.json"))
        candidates = synthesize_lifetime_schedules(analysis)
        schedule = read(ROOT / "fixtures/platform/seeded_lifetime.schedule.json")
        lowering = read(ROOT / "fixtures/lowering/public_seeded.target.json")
        return analysis, candidates, schedule, lowering

    def test_candidate_lowers_to_hash_bound_kprobe_plan(self):
        analysis, candidates, schedule, lowering = self.inputs()
        validation = validate_target_lowering(analysis, candidates, schedule, lowering)
        plan = compile_target_controller(analysis, candidates, schedule, lowering)
        self.assertEqual(validation["point_count"], 5)
        self.assertEqual(validation["role_count"], 2)
        self.assertEqual(plan["target"]["binary_sha256"], analysis["binary_sha256"])
        self.assertEqual(plan["points"][0]["selector"]["kind"], "symbol-offset")
        self.assertEqual(plan["points"][0]["identity_capture"], {"kind": "register", "index": 19})
        self.assertEqual(plan["points"][-1]["counter_index"], 0)
        self.assertEqual(len(plan["plan_sha256"]), 64)

    def test_public_input_and_output_contract_schemas_are_well_formed(self):
        for name, schema_id in (
            ("target_lowering.schema.json", "urn:rehostrace:schema:target-lowering:v1"),
            ("controller_plan.schema.json", "urn:rehostrace:schema:controller-plan:v1"),
        ):
            document = read(ROOT / "schemas" / name)
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(document["$id"], schema_id)

    def test_header_contains_offsets_roles_predicates_and_identity_capture(self):
        analysis, candidates, schedule, lowering = self.inputs()
        plan = compile_target_controller(analysis, candidates, schedule, lowering)
        header = render_target_controller_header(plan)
        self.assertIn("REHOSTRACE_CONTROLLER_PLAN_SHA256", header)
        self.assertIn('"public_seed_rx_reset", 0x20UL', header)
        self.assertIn("REHOSTRACE_CAPTURE_REGISTER", header)
        self.assertIn("rehostrace_lowered_predicates", header)
        self.assertIn("rehostrace_lowered_counters", header)
        self.assertIn("REHOSTRACE_TARGET_IDENTITY_SAME 1U", header)
        self.assertIn(plan["plan_sha256"], header)

    def test_binary_identity_drift_is_rejected(self):
        analysis, candidates, schedule, lowering = self.inputs()
        lowering["target"]["binary_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "binary identity"):
            compile_target_controller(analysis, candidates, schedule, lowering)

    def test_missing_point_binding_is_rejected(self):
        analysis, candidates, schedule, lowering = self.inputs()
        lowering["point_bindings"].pop()
        with self.assertRaisesRegex(ValueError, "exactly cover"):
            compile_target_controller(analysis, candidates, schedule, lowering)

    def test_unknown_role_is_rejected(self):
        analysis, candidates, schedule, lowering = self.inputs()
        lowering["point_bindings"][0]["role"] = "actor.unknown"
        with self.assertRaisesRegex(ValueError, "unknown role"):
            compile_target_controller(analysis, candidates, schedule, lowering)

    def test_candidate_integrity_drift_is_rejected(self):
        analysis, candidates, schedule, lowering = self.inputs()
        candidates = copy.deepcopy(candidates)
        candidates["schedules"][0]["oracle"]["sink_count"] = 99
        with self.assertRaisesRegex(ValueError, "integrity"):
            compile_target_controller(analysis, candidates, schedule, lowering)


if __name__ == "__main__":
    unittest.main()

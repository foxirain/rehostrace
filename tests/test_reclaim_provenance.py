import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (  # noqa: E402
    evaluate_reclaim_oracle,
    validate_receipt,
    validate_reclaim_oracle,
)


class ReclaimProvenanceTests(unittest.TestCase):
    def oracle(self):
        return json.loads(
            (ROOT / "fixtures/platform/target_owned_reclaim.oracle.json").read_text()
        )

    def observations(self):
        return [
            json.loads(line)
            for line in (
                ROOT / "fixtures/platform/target_owned_reclaim.observations.jsonl"
            )
            .read_text()
            .splitlines()
            if line.strip()
        ]

    def by_id(self, observations, observation_id):
        return next(record for record in observations if record["id"] == observation_id)

    def test_public_fixture_proves_target_owned_foreign_free(self):
        validation = validate_reclaim_oracle(self.oracle())
        result = evaluate_reclaim_oracle(self.oracle(), self.observations())
        self.assertEqual(validation["role_count"], 7)
        self.assertTrue(validation["requires_post_free_alias"])
        self.assertEqual(result["verdict"], "positive")
        self.assertEqual(result["identity_tokens"], ["slot.07"])
        self.assertEqual(
            result["generation_tokens"],
            ["gen.alias", "gen.original", "gen.replacement"],
        )
        self.assertEqual(result["replacement_producer"], "target")
        self.assertTrue(all(result["checks"].values()))

    def test_controller_allocated_replacement_is_negative(self):
        observations = self.observations()
        self.by_id(observations, "obs.replacement-alloc")["producer"] = "controller"
        result = evaluate_reclaim_oracle(self.oracle(), observations)
        self.assertEqual(result["verdict"], "negative")
        self.assertFalse(result["checks"]["provenance:target-producer"])

    def test_missing_foreign_free_is_inconclusive(self):
        observations = [
            record
            for record in self.observations()
            if record["id"] != "obs.foreign-free"
        ]
        result = evaluate_reclaim_oracle(self.oracle(), observations)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertFalse(result["checks"]["present:foreign_free"])

    def test_same_generation_reuse_is_negative(self):
        observations = self.observations()
        replacement = self.by_id(observations, "obs.replacement-alloc")
        replacement["generation"] = "gen.original"
        self.by_id(observations, "obs.stale-read")["generation"] = "gen.original"
        self.by_id(observations, "obs.foreign-free")["generation"] = "gen.original"
        result = evaluate_reclaim_oracle(self.oracle(), observations)
        self.assertEqual(result["verdict"], "negative")
        self.assertFalse(result["checks"]["identity:new-generation"])

    def test_read_to_write_value_drift_is_negative(self):
        observations = self.observations()
        self.by_id(observations, "obs.list-write")["value"] = "pointer.other"
        result = evaluate_reclaim_oracle(self.oracle(), observations)
        self.assertEqual(result["verdict"], "negative")
        self.assertFalse(result["checks"]["effect:read-to-write"])

    def test_reordered_boundary_allocation_is_negative(self):
        observations = self.observations()
        self.by_id(observations, "obs.replacement-alloc")["sequence"] = 15
        result = evaluate_reclaim_oracle(self.oracle(), observations)
        self.assertEqual(result["verdict"], "negative")
        self.assertFalse(result["checks"]["sequence:required"])

    def test_duplicate_observation_id_is_inconclusive(self):
        observations = self.observations()
        observations.append(copy.deepcopy(observations[-1]))
        result = evaluate_reclaim_oracle(self.oracle(), observations)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["duplicate_observation_ids"], ["obs.post-free-alias"])

    def test_required_producer_cannot_be_forbidden(self):
        oracle = self.oracle()
        oracle["provenance"]["forbidden_producers"].append("target")
        with self.assertRaisesRegex(ValueError, "cannot also be forbidden"):
            validate_reclaim_oracle(oracle)

    def test_required_sequence_cannot_omit_a_role(self):
        oracle = self.oracle()
        oracle["required_sequence"].pop()
        with self.assertRaisesRegex(ValueError, "canonical reclaim sequence"):
            validate_reclaim_oracle(oracle)

    def test_oracle_cannot_redefine_reclaim_order(self):
        oracle = self.oracle()
        oracle["required_sequence"][1:3] = reversed(
            oracle["required_sequence"][1:3]
        )
        with self.assertRaisesRegex(ValueError, "canonical reclaim sequence"):
            validate_reclaim_oracle(oracle)

    def test_stale_actor_cannot_be_replacement_owner(self):
        oracle = self.oracle()
        oracle["ownership"]["stale_actor"] = oracle["ownership"][
            "replacement_owner"
        ]
        with self.assertRaisesRegex(ValueError, "cannot be the replacement owner"):
            validate_reclaim_oracle(oracle)

    def test_demo_emits_receipt_with_new_claim_classes(self):
        subprocess.run(
            [sys.executable, "tools/run_reclaim_provenance_demo.py"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        receipt = json.loads(
            (ROOT / "out/reclaim_provenance/evidence-receipt.json").read_text()
        )
        validation = validate_receipt(receipt)
        self.assertEqual(validation["status"], "passed")
        self.assertIn(
            "mechanism.allocation-provenance",
            receipt["fidelity"]["transfer"]["asserted_claims"],
        )
        self.assertIn(
            "finding.foreign-owner-free",
            receipt["fidelity"]["transfer"]["asserted_claims"],
        )

    def test_cli_evaluates_public_fixture(self):
        completed = subprocess.run(
            [
                sys.executable,
                "tools/rehostrace_cli.py",
                "evaluate-reclaim",
                "fixtures/platform/target_owned_reclaim.oracle.json",
                "fixtures/platform/target_owned_reclaim.observations.jsonl",
            ],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["verdict"], "positive")
        self.assertTrue(all(result["checks"].values()))


if __name__ == "__main__":
    unittest.main()

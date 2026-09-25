import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (
    CausalTrace,
    build_receipt,
    compile_ablation,
    compile_binding,
    compile_evidence_transfer_bridge,
    compile_schedule,
    evaluate_oracle,
    gate_key,
    plan_exhaustive_search,
    render_c_header,
    render_binding_header,
    synthesize_schedule,
    summarize_search,
    validate_oracle,
    validate_receipt,
    validate_evidence_transfer_bridge,
    validate_evidence_transfer_policy,
    validate_schedule,
    verify_receipt_artifacts,
)


class PlatformContractTests(unittest.TestCase):
    def schedule(self):
        return json.loads((ROOT / "fixtures/platform/seeded_lifetime.schedule.json").read_text())

    def constraints(self):
        return json.loads(
            (ROOT / "fixtures/platform/seeded_lifetime.constraints.json").read_text()
        )

    def oracle(self):
        return json.loads((ROOT / "fixtures/platform/seeded_lifetime.oracle.json").read_text())

    def trace(self):
        return CausalTrace(
            json.loads((ROOT / "fixtures/platform/async_boundary.causal.json").read_text())
        )

    def binding(self):
        return json.loads((ROOT / "fixtures/platform/seeded_boundary.binding.json").read_text())

    def nogate_schedule(self):
        return json.loads(
            (ROOT / "fixtures/platform/seeded_lifetime.nogate.schedule.json").read_text()
        )

    def nogate_binding(self):
        return json.loads(
            (ROOT / "fixtures/platform/seeded_boundary.nogate.binding.json").read_text()
        )

    def ablation(self):
        return json.loads(
            (ROOT / "fixtures/platform/causal_order.ablation.json").read_text()
        )

    def observations(self):
        return [
            json.loads(line)
            for line in (ROOT / "fixtures/platform/seeded_observations.jsonl")
            .read_text()
            .splitlines()
            if line.strip()
        ]

    def test_schedule_compiles_to_deterministic_masks_and_header(self):
        schedule = self.schedule()
        validation = validate_schedule(schedule)
        plan = compile_schedule(schedule)
        header = render_c_header(schedule)
        self.assertEqual(validation["point_count"], 5)
        self.assertEqual(plan["points"][0]["enter_mask"], 1)
        self.assertEqual(plan["points"][0]["wait_mask"], 2)
        self.assertIn("rehostrace_seed_a_object_released", header)
        self.assertIn(validation["schedule_sha256"], header)

    def test_constraints_synthesize_checked_in_schedule_exactly(self):
        schedule, report = synthesize_schedule(self.constraints())
        self.assertEqual(schedule, self.schedule())
        self.assertEqual(
            report["schedule_sha256"],
            "605a918376288ddab1ced8392bfaf07f43abcd828c0dd44bf8458013c8e86f2e",
        )
        self.assertEqual(report["point_count"], 5)
        self.assertEqual(report["gate_count"], 3)

    def test_constraints_reject_phase_cycle(self):
        constraints = self.constraints()
        constraints["milestones"].append(
            {
                "signal": "cycle.signal",
                "point": "a.object-released",
                "phase": "release",
            }
        )
        constraints["signal_order"].append("cycle.signal")
        constraints["gates"].append(
            {
                "after_signal": "cycle.signal",
                "before_release_of": "a.object-released",
            }
        )
        with self.assertRaisesRegex(ValueError, "self-dependent phase"):
            synthesize_schedule(constraints)

    def test_constraints_reject_counter_gate_until_phase_is_modeled(self):
        constraints = self.constraints()
        constraints["gates"].append(
            {
                "after_signal": "second-free",
                "before_release_of": "a.object-released",
            }
        )
        with self.assertRaisesRegex(ValueError, "counter-produced gate"):
            synthesize_schedule(constraints)

    def test_exhaustive_search_plans_every_gate_subset(self):
        manifest, documents = plan_exhaustive_search(
            self.constraints(),
            self.binding(),
            self.trace(),
            search_id="public.seeded.search-test",
            repetitions=2,
        )
        self.assertEqual(len(manifest["gate_universe"]), 3)
        self.assertEqual(len(manifest["candidates"]), 8)
        self.assertEqual(len(documents), 8)
        self.assertEqual(
            {record["gate_count"] for record in manifest["candidates"]},
            {0, 1, 2, 3},
        )

    def test_search_summary_preserves_inconclusive_and_finds_global_minimum(self):
        manifest, _ = plan_exhaustive_search(
            self.constraints(),
            self.binding(),
            self.trace(),
            search_id="public.seeded.search-summary",
            repetitions=2,
        )
        candidates = manifest["candidates"]
        chosen = next(record for record in candidates if record["gate_count"] == 2)
        trials = []
        for candidate in candidates:
            for run in (1, 2):
                verdict = "positive" if candidate["candidate_id"] == chosen["candidate_id"] else "negative"
                trials.append(
                    {
                        "candidate_id": candidate["candidate_id"],
                        "run": run,
                        "verdict": verdict,
                    }
                )
        result = summarize_search(manifest, trials)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["globally_minimal_gate_count"], 2)
        self.assertEqual(result["globally_minimal_candidates"], [chosen["candidate_id"]])

        incomplete = summarize_search(manifest, trials[:-1])
        self.assertEqual(incomplete["status"], "inconclusive")

    def test_gate_key_is_semantic_and_stable(self):
        self.assertEqual(
            gate_key(self.constraints()["gates"][0]),
            "b.lock-pre::a.object-released",
        )

    def test_schedule_rejects_wait_without_signal_producer(self):
        schedule = self.schedule()
        schedule["points"][0]["wait_for"] = ["second-free"]
        schedule["counters"] = []
        schedule["points"][-1].pop("counter")
        with self.assertRaisesRegex(ValueError, "no producer"):
            validate_schedule(schedule)

    def test_boundary_binding_preserves_concurrent_projection(self):
        plan = compile_binding(self.binding(), self.trace(), self.schedule())
        self.assertEqual(plan["trace_sha256"], self.trace().digest)
        self.assertEqual([item["event_id"] for item in plan["actions"]], [
            "e.tx-disconnect",
            "e.link-loss-irq",
        ])
        header = render_binding_header(self.binding(), self.trace(), self.schedule())
        self.assertIn("REHOSTRACE_BOUNDARY_ACTOR_A_PAYLOAD 0x41U", header)
        self.assertIn("REHOSTRACE_BOUNDARY_ACTOR_B_START_MASK 0x00000001U", header)
        self.assertIn("REHOSTRACE_BOUNDARY_TRACE_SHA256", header)

    def test_boundary_binding_rejects_schedule_identity_drift(self):
        binding = self.binding()
        binding["schedule_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "schedule_sha256"):
            compile_binding(binding, self.trace(), self.schedule())

    def test_boundary_binding_rejects_ordered_events_in_one_launch_group(self):
        binding = self.binding()
        binding["actions"][1]["event_id"] = "e.timeout"
        with self.assertRaisesRegex(ValueError, "causally ordered"):
            compile_binding(binding, self.trace(), self.schedule())

    def test_boundary_binding_digest_ignores_action_document_order(self):
        binding = self.binding()
        original = compile_binding(binding, self.trace(), self.schedule())
        binding["actions"].reverse()
        permuted = compile_binding(binding, self.trace(), self.schedule())
        self.assertEqual(original["binding_sha256"], permuted["binding_sha256"])
        self.assertEqual(original["actions"], permuted["actions"])

    def test_ablation_preserves_dag_concurrency_and_exposes_timestamp_loss(self):
        plan = compile_ablation(
            self.ablation(), self.trace(), self.nogate_binding(), self.nogate_schedule()
        )
        policies = {record["id"]: record for record in plan["policies"]}
        self.assertTrue(policies["causal-dag"]["preserves_concurrency"])
        self.assertEqual(policies["fixed-a-then-b"]["action_order"], ["actor.a", "actor.b"])
        self.assertEqual(policies["fixed-b-then-a"]["action_order"], ["actor.b", "actor.a"])
        self.assertEqual(policies["naive-timestamp"]["action_order"], ["actor.b", "actor.a"])
        self.assertTrue(policies["naive-timestamp"]["cross_domain_timestamp_comparison"])

    def test_ablation_rejects_silent_cross_clock_timestamp_order(self):
        document = self.ablation()
        document["policies"][-1].pop("acknowledge_cross_domain_unsoundness")
        with self.assertRaisesRegex(ValueError, "acknowledge"):
            compile_ablation(
                document, self.trace(), self.nogate_binding(), self.nogate_schedule()
            )

    def test_oracle_accepts_same_object_two_free_fixture(self):
        result = evaluate_oracle(self.oracle(), self.observations())
        self.assertEqual(result["verdict"], "positive")
        self.assertEqual(result["identity_tokens"], ["public-object-token-1"])
        self.assertTrue(all(result["checks"].values()))

    def test_oracle_rejects_identity_drift(self):
        observations = self.observations()
        observations[4]["captures"]["object"] = "public-object-token-2"
        result = evaluate_oracle(self.oracle(), observations)
        self.assertEqual(result["verdict"], "negative")
        self.assertFalse(result["checks"]["identity:equal"])

    def test_oracle_marks_missing_sink_inconclusive(self):
        observations = self.observations()
        observations = [
            item
            for index, item in enumerate(observations)
            if not (item.get("type") == "point" and item.get("point") == "free.pre" and index == 5)
        ]
        result = evaluate_oracle(self.oracle(), observations)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertFalse(result["checks"]["point:free.pre"])

    def test_c_header_rejects_unsupported_module_offset_selector(self):
        schedule = self.schedule()
        schedule["points"][0]["selector"] = {
            "kind": "module-offset",
            "module": "public_fixture",
            "offset": 16,
            "expected_bytes_sha256": "0" * 64,
        }
        with self.assertRaisesRegex(ValueError, "symbol selectors only"):
            render_c_header(schedule)

    def test_receipt_is_portable_and_self_hashing(self):
        oracle_result = evaluate_oracle(self.oracle(), self.observations())
        receipt = build_receipt(
            receipt_id="public.unit.receipt",
            experiment="unit test",
            status="passed",
            root=ROOT,
            inputs=[
                {
                    "role": "oracle",
                    "path": ROOT / "fixtures/platform/seeded_lifetime.oracle.json",
                    "disclosure": "public",
                }
            ],
            execution={
                "architecture": "portable-model",
                "executor": "unit-test",
                "event_order": ["event.1"],
            },
            oracle=oracle_result,
            fidelity={
                "track": "public.synthetic.model",
                "dimensions": {"oracle": "demonstrated", "stock": "not-applicable"},
                "transfer": {
                    "allowed_claims": ["artifact.reproducibility"],
                    "forbidden_claims": ["stock.harmful-consequence"],
                    "asserted_claims": ["artifact.reproducibility"],
                },
            },
            claim_boundary="Public fixture only.",
        )
        result = validate_receipt(receipt)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(Path(receipt["inputs"][0]["path"]).is_absolute())

    def test_receipt_rejects_absolute_path(self):
        oracle_result = evaluate_oracle(self.oracle(), self.observations())
        receipt = build_receipt(
            receipt_id="public.unit.absolute",
            experiment="unit test",
            status="passed",
            root=ROOT,
            inputs=[
                {
                    "role": "oracle",
                    "path": ROOT / "fixtures/platform/seeded_lifetime.oracle.json",
                    "disclosure": "public",
                }
            ],
            execution={"architecture": "model", "executor": "test", "event_order": []},
            oracle=oracle_result,
            fidelity={
                "track": "public.synthetic.model",
                "dimensions": {"oracle": "demonstrated"},
                "transfer": {
                    "allowed_claims": ["artifact.reproducibility"],
                    "forbidden_claims": ["stock.harmful-consequence"],
                    "asserted_claims": ["artifact.reproducibility"],
                },
            },
            claim_boundary="Public fixture only.",
        )
        receipt["inputs"][0]["path"] = "/private/oracle.json"
        with self.assertRaisesRegex(ValueError, "portable"):
            validate_receipt(receipt)

    def test_receipt_rejects_nonportable_backslash_path(self):
        oracle_result = evaluate_oracle(self.oracle(), self.observations())
        receipt = build_receipt(
            receipt_id="public.unit.backslash",
            experiment="unit test",
            status="passed",
            root=ROOT,
            inputs=[
                {
                    "role": "oracle",
                    "path": ROOT / "fixtures/platform/seeded_lifetime.oracle.json",
                    "disclosure": "public",
                }
            ],
            execution={"architecture": "model", "executor": "test", "event_order": []},
            oracle=oracle_result,
            fidelity={
                "track": "public.synthetic.model",
                "dimensions": {"oracle": "demonstrated"},
                "transfer": {
                    "allowed_claims": ["artifact.reproducibility"],
                    "forbidden_claims": ["stock.harmful-consequence"],
                    "asserted_claims": ["artifact.reproducibility"],
                },
            },
            claim_boundary="Public fixture only.",
        )
        receipt["inputs"][0]["path"] = "..\\private\\oracle.json"
        with self.assertRaisesRegex(ValueError, "portable"):
            validate_receipt(receipt)

    def test_receipt_rejects_forbidden_claim_promotion(self):
        oracle_result = evaluate_oracle(self.oracle(), self.observations())
        receipt = build_receipt(
            receipt_id="public.unit.claim-transfer",
            experiment="unit test",
            status="passed",
            root=ROOT,
            inputs=[
                {
                    "role": "oracle",
                    "path": ROOT / "fixtures/platform/seeded_lifetime.oracle.json",
                    "disclosure": "public",
                }
            ],
            execution={"architecture": "model", "executor": "test", "event_order": []},
            oracle=oracle_result,
            fidelity={
                "track": "public.synthetic.model",
                "dimensions": {"oracle": "demonstrated"},
                "transfer": {
                    "allowed_claims": ["artifact.reproducibility"],
                    "forbidden_claims": ["stock.harmful-consequence"],
                    "asserted_claims": ["artifact.reproducibility"],
                },
            },
            claim_boundary="Public fixture only.",
        )
        receipt["fidelity"]["transfer"]["asserted_claims"] = [
            "stock.harmful-consequence"
        ]
        with self.assertRaisesRegex(ValueError, "not allowed"):
            validate_receipt(receipt)

    def test_passed_receipt_requires_positive_complete_oracle(self):
        oracle_result = evaluate_oracle(self.oracle(), self.observations())
        oracle_result["verdict"] = "negative"
        with self.assertRaisesRegex(ValueError, "complete positive"):
            build_receipt(
                receipt_id="public.unit.false-pass",
                experiment="unit test",
                status="passed",
                root=ROOT,
                inputs=[
                    {
                        "role": "oracle",
                        "path": ROOT / "fixtures/platform/seeded_lifetime.oracle.json",
                        "disclosure": "public",
                    }
                ],
                execution={"architecture": "model", "executor": "test", "event_order": []},
                oracle=oracle_result,
                fidelity={
                    "track": "public.synthetic.model",
                    "dimensions": {"oracle": "demonstrated"},
                    "transfer": {
                        "allowed_claims": ["artifact.reproducibility"],
                        "forbidden_claims": ["stock.harmful-consequence"],
                        "asserted_claims": ["artifact.reproducibility"],
                    },
                },
                claim_boundary="Public fixture only.",
            )

    def test_receipt_artifact_verification_detects_drift(self):
        oracle_result = evaluate_oracle(self.oracle(), self.observations())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "fixture.txt"
            artifact.write_text("original", encoding="utf-8")
            receipt = build_receipt(
                receipt_id="public.unit.artifact-verify",
                experiment="unit test",
                status="passed",
                root=root,
                inputs=[{"role": "fixture", "path": artifact, "disclosure": "public"}],
                execution={"architecture": "model", "executor": "test", "event_order": []},
                oracle=oracle_result,
                fidelity={
                    "track": "public.synthetic.model",
                    "dimensions": {"oracle": "demonstrated"},
                    "transfer": {
                        "allowed_claims": ["artifact.reproducibility"],
                        "forbidden_claims": ["stock.harmful-consequence"],
                        "asserted_claims": ["artifact.reproducibility"],
                    },
                },
                claim_boundary="Public fixture only.",
            )
            self.assertEqual(
                verify_receipt_artifacts(receipt, root)["artifact_status"], "passed"
            )
            artifact.write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verify_receipt_artifacts(receipt, root)

    def test_json_schemas_are_well_formed(self):
        for name in (
            "causal_trace.schema.json",
            "boundary_binding.schema.json",
            "schedule_constraints.schema.json",
            "schedule_search.schema.json",
            "replay_ablation.schema.json",
            "replay_ablation_result.schema.json",
            "lifetime_schedule.schema.json",
            "lifetime_oracle.schema.json",
            "evidence_receipt.schema.json",
            "evidence_transfer_policy.schema.json",
            "evidence_transfer_bridge.schema.json",
            "observer_calibration_policy.schema.json",
            "observer_calibration.schema.json",
        ):
            document = json.loads((ROOT / "schemas" / name).read_text())
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")


if __name__ == "__main__":
    unittest.main()

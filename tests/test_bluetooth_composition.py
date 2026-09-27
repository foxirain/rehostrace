import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (
    CausalTrace,
    compose_bluetooth_traces,
    generate_bluetooth_linearizations,
    linearization_pair_coverage,
    validate_bluetooth_composition,
)


class BluetoothCompositionTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(
            (ROOT / "fixtures/bluetooth/cross_profile.composition.json").read_text()
        )
        self.traces = {
            "classic-avdtp": json.loads(
                (ROOT / "fixtures/bluetooth/hci_l2cap_avdtp.causal.json").read_text()
            ),
            "classic-sdp": json.loads(
                (
                    ROOT
                    / "fixtures/bluetooth/sdp_service_search_attribute.causal.json"
                ).read_text()
            ),
            "le-att-gatt": json.loads(
                (ROOT / "fixtures/bluetooth/att_gatt.causal.json").read_text()
            ),
        }

    def composed_trace(self):
        return compose_bluetooth_traces(self.document, self.traces)

    def test_composition_policy_validation_is_hash_stable(self):
        first = validate_bluetooth_composition(self.document)
        second = validate_bluetooth_composition(copy.deepcopy(self.document))
        self.assertEqual(first, second)
        self.assertEqual(first["branch_count"], 3)
        self.assertEqual(first["random_seed_count"], 16)

    def test_composition_shares_one_ready_event_and_namespaces_branch_state(self):
        original = copy.deepcopy(self.traces)
        composed = self.composed_trace()
        trace = CausalTrace(composed)
        self.assertEqual(self.traces, original)
        ready = [
            event
            for event in trace.events.values()
            if event["boundary"]["operation"] == "hci.controller.ready"
        ]
        self.assertEqual([event["id"] for event in ready], ["shared.controller-ready"])
        self.assertEqual(
            composed["composition"]["branches"], self.document["branches"]
        )
        for event in trace.events.values():
            branch = event.get("correlation", {}).get("composition_branch")
            if branch is None:
                continue
            self.assertTrue(event["id"].startswith(f"{branch}:"))
            for key in (
                "command_id",
                "sdu_id",
                "procedure_id",
                "address_token",
                "peer_address_token",
                "transaction_id",
            ):
                value = event["attributes"].get(key)
                if isinstance(value, str):
                    self.assertTrue(value.startswith(f"{branch}:"), (event["id"], key))

    def test_trace_identity_set_and_handle_collisions_fail_closed(self):
        missing = copy.deepcopy(self.traces)
        missing.pop("classic-sdp")
        with self.assertRaisesRegex(ValueError, "trace identities differ"):
            compose_bluetooth_traces(self.document, missing)

        collision = copy.deepcopy(self.traces)
        connection = next(
            event
            for event in collision["le-att-gatt"]["events"]
            if event["boundary"]["operation"] == "hci.le.connection.complete"
        )
        connection["attributes"]["handle"] = 64
        with self.assertRaisesRegex(ValueError, "collides in branches"):
            compose_bluetooth_traces(self.document, collision)

    def test_controller_credit_disagreement_is_rejected(self):
        traces = copy.deepcopy(self.traces)
        ready = next(
            event
            for event in traces["classic-sdp"]["events"]
            if event["boundary"]["operation"] == "hci.controller.ready"
        )
        ready["attributes"]["command_credits"] = 2
        with self.assertRaisesRegex(ValueError, "command credits"):
            compose_bluetooth_traces(self.document, traces)

    def test_generated_linearizations_are_deterministic_causal_extensions(self):
        trace = CausalTrace(self.composed_trace())
        first = generate_bluetooth_linearizations(trace, self.document)
        second = generate_bluetooth_linearizations(trace, self.document)
        self.assertEqual(first, second)
        self.assertGreaterEqual(len(first), 2)
        self.assertEqual(len({record["event_order_sha256"] for record in first}), len(first))
        for policy in first:
            completed = []
            for event_id in policy["event_order"]:
                self.assertIn(event_id, trace.ready(completed), policy["policy_id"])
                completed.append(event_id)
            self.assertEqual(set(completed), set(trace.events))

        coverage = linearization_pair_coverage(trace, first)
        self.assertGreater(coverage["concurrent_pair_count"], 0)
        self.assertGreater(coverage["both_orders_observed"], 0)
        self.assertGreater(coverage["both_orders_fraction"], 0.0)
        self.assertLessEqual(coverage["both_orders_fraction"], 1.0)

    def test_invalid_policy_bounds_and_nonconcurrent_coverage_are_explicit(self):
        document = copy.deepcopy(self.document)
        document["random_seeds"] = [1, 1]
        with self.assertRaisesRegex(ValueError, "unique 32-bit"):
            validate_bluetooth_composition(document)

        linear = CausalTrace(
            json.loads((ROOT / "fixtures/bluetooth/smp_pairing.causal.json").read_text())
        )
        policy = {
            "policy_id": "only-order",
            "event_order": linear.validation["topological_order"],
        }
        coverage = linearization_pair_coverage(linear, [policy])
        self.assertEqual(coverage["concurrent_pair_count"], 0)
        self.assertEqual(coverage["both_orders_fraction"], 1.0)
        self.assertTrue(coverage["all_concurrent_pairs_reversed"])


if __name__ == "__main__":
    unittest.main()

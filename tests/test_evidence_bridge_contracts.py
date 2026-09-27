import copy
import hashlib
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
    compile_evidence_transfer_bridge,
    validate_evidence_transfer_bridge,
    validate_evidence_transfer_policy,
)


def canonical_sha256(document):
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def rehash_receipt(receipt):
    material = copy.deepcopy(receipt)
    material.pop("integrity", None)
    receipt["integrity"] = {"content_sha256": canonical_sha256(material)}


class EvidenceTransferBridgeContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.trace_document = json.loads(
            (ROOT / "fixtures/platform/async_boundary.causal.json").read_text()
        )
        self.trace = CausalTrace(self.trace_document)
        self.policy = json.loads(
            (ROOT / "fixtures/platform/seeded_evidence_transfer.policy.json").read_text()
        )
        self.trace_path = self.root / "trace.json"
        self.trace_path.write_text(json.dumps(self.trace_document, sort_keys=True))

    @property
    def transfer(self):
        return copy.deepcopy(self.policy["transfer"])

    def make_single_receipt(self):
        return build_receipt(
            receipt_id="public.seeded.single-run",
            experiment="public seeded concurrent lifetime run",
            status="passed",
            root=self.root,
            inputs=[
                {
                    "role": "causal-trace",
                    "path": self.trace_path,
                    "disclosure": "public",
                }
            ],
            execution={
                "architecture": "arm64-fixture",
                "executor": "public-seeded-executor",
                "event_order": ["e.link-loss-irq", "e.tx-disconnect"],
                "causal_trace_sha256": self.trace.digest,
                "projected_events": ["e.tx-disconnect", "e.link-loss-irq"],
            },
            oracle={
                "oracle_id": "public.seeded.double-free",
                "verdict": "positive",
                "checks": {
                    name: True
                    for name in self.policy["requirements"]["single_receipt"][
                        "required_oracle_checks"
                    ]
                },
                "identity_tokens": ["public-object-token-1"],
            },
            fidelity={
                "track": "public.seeded-fixture",
                "dimensions": copy.deepcopy(
                    self.policy["requirements"]["single_receipt"][
                        "required_fidelity_dimensions"
                    ]
                ),
                "transfer": self.transfer,
            },
            claim_boundary="This receipt covers one public synthetic fixture run only.",
        )

    def make_campaign(self):
        campaign_id = "public.seeded.campaign-20"
        result = {
            "campaign_id": campaign_id,
            "repetitions": 20,
            "positive": 20,
            "negative": 0,
            "inconclusive": 0,
            "checks": {
                "all_trial_receipts_rehashed": True,
                "all_trials_positive": True,
                "artifact_identity_stable": True,
                "zero_inconclusive": True,
            },
        }
        result_path = self.root / "campaign-result.json"
        result_path.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")))
        result_sha256 = hashlib.sha256(result_path.read_bytes()).hexdigest()
        receipt = build_receipt(
            receipt_id=campaign_id,
            experiment="public seeded repeated lifetime campaign",
            status="passed",
            root=self.root,
            inputs=[
                {
                    "role": "campaign-result",
                    "path": result_path,
                    "disclosure": "public",
                }
            ],
            execution={
                "architecture": "arm64-fixture",
                "executor": "public-seeded-campaign",
                "event_order": [],
                "repetitions": 20,
                "positive": 20,
            },
            oracle={
                "oracle_id": "public.seeded.campaign-oracle",
                "verdict": "positive",
                "checks": copy.deepcopy(result["checks"]),
                "identity_tokens": ["public-object-token-1"],
            },
            fidelity={
                "track": "public.seeded-campaign",
                "dimensions": {"repeated_execution": "demonstrated"},
                "transfer": {
                    "allowed_claims": ["artifact.reproducibility"],
                    "asserted_claims": ["artifact.reproducibility"],
                    "forbidden_claims": copy.deepcopy(
                        self.policy["transfer"]["forbidden_claims"]
                    ),
                },
            },
            claim_boundary="This receipt covers the public synthetic campaign only.",
        )
        return receipt, result, result_sha256

    def compile_bridge(self):
        campaign_receipt, campaign_result, campaign_sha256 = self.make_campaign()
        return compile_evidence_transfer_bridge(
            self.policy,
            self.trace,
            self.make_single_receipt(),
            campaign_receipt,
            campaign_result,
            campaign_result_sha256=campaign_sha256,
        )

    def test_policy_binds_a_concurrent_shared_subject_pair(self):
        validation = validate_evidence_transfer_policy(self.policy, self.trace)
        self.assertEqual(validation["status"], "passed")
        self.assertEqual(validation["pair"]["relation"], "concurrent")
        self.assertTrue(validation["pair"]["shared_subject"])
        self.assertTrue(validation["pair"]["shared_session"])

    def test_bridge_compiles_and_revalidates_hash_bound_evidence(self):
        bridge = self.compile_bridge()
        self.assertEqual(bridge["status"], "passed")
        self.assertEqual(bridge["lifetime_evidence"]["verified_runs"], 20)
        self.assertFalse(
            bridge["lifetime_evidence"]["object_identity_tokens_disclosed"]
        )
        validation = validate_evidence_transfer_bridge(bridge)
        self.assertEqual(validation["verified_runs"], 20)
        self.assertEqual(validation["content_sha256"], bridge["integrity"]["content_sha256"])

    def test_causally_ordered_policy_pair_is_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy["pair"][0] = {
            "role": "timeout-origin",
            "event_id": "e.timeout",
            "operation": "disconnect-timeout.expired",
        }
        policy["pair"][1] = {
            "role": "disconnect-origin",
            "event_id": "e.tx-disconnect",
            "operation": "disconnect.request",
        }
        with self.assertRaisesRegex(ValueError, "causally ordered"):
            validate_evidence_transfer_policy(policy, self.trace)

    def test_single_receipt_projection_and_identity_drift_fail_closed(self):
        campaign_receipt, campaign_result, campaign_sha256 = self.make_campaign()
        single = self.make_single_receipt()
        single["execution"]["projected_events"] = ["e.tx-disconnect"]
        rehash_receipt(single)
        with self.assertRaisesRegex(ValueError, "project exactly"):
            compile_evidence_transfer_bridge(
                self.policy,
                self.trace,
                single,
                campaign_receipt,
                campaign_result,
                campaign_result_sha256=campaign_sha256,
            )

        single = self.make_single_receipt()
        single["oracle"]["identity_tokens"].append("unexpected-object")
        rehash_receipt(single)
        with self.assertRaisesRegex(ValueError, "cardinality"):
            compile_evidence_transfer_bridge(
                self.policy,
                self.trace,
                single,
                campaign_receipt,
                campaign_result,
                campaign_result_sha256=campaign_sha256,
            )

    def test_campaign_result_digest_and_counts_are_enforced(self):
        campaign_receipt, campaign_result, campaign_sha256 = self.make_campaign()
        with self.assertRaisesRegex(ValueError, "hash-bound"):
            compile_evidence_transfer_bridge(
                self.policy,
                self.trace,
                self.make_single_receipt(),
                campaign_receipt,
                campaign_result,
                campaign_result_sha256="e" * 64,
            )

        campaign_result["positive"] = 19
        with self.assertRaisesRegex(ValueError, "positive count"):
            compile_evidence_transfer_bridge(
                self.policy,
                self.trace,
                self.make_single_receipt(),
                campaign_receipt,
                campaign_result,
                campaign_result_sha256=campaign_sha256,
            )

    def test_forbidden_claims_cannot_be_dropped_by_source_receipts(self):
        campaign_receipt, campaign_result, campaign_sha256 = self.make_campaign()
        single = self.make_single_receipt()
        single["fidelity"]["transfer"]["forbidden_claims"].pop()
        rehash_receipt(single)
        with self.assertRaisesRegex(ValueError, "preserve all bridge forbidden claims"):
            compile_evidence_transfer_bridge(
                self.policy,
                self.trace,
                single,
                campaign_receipt,
                campaign_result,
                campaign_result_sha256=campaign_sha256,
            )

    def test_policy_claim_promotion_and_bridge_tampering_are_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy["transfer"]["asserted_claims"].append("impact.code-execution")
        with self.assertRaisesRegex(ValueError, "asserted bridge claims are not allowed"):
            validate_evidence_transfer_policy(policy, self.trace)

        bridge = self.compile_bridge()
        bridge["lifetime_evidence"]["verified_runs"] = 21
        with self.assertRaisesRegex(ValueError, "lifetime evidence is incomplete|integrity"):
            validate_evidence_transfer_bridge(bridge)


if __name__ == "__main__":
    unittest.main()

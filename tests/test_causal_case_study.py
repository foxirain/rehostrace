import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from run_causal_case_study import build_case_study, content_sha256


class CausalCaseStudyTests(unittest.TestCase):
    def test_case_study_quantifies_timestamp_information_loss(self):
        result = build_case_study(ROOT)
        self.assertEqual(result["projected_pair"]["relation"], "concurrent")
        self.assertEqual(result["causal_dag"]["candidate_order_count"], 2)
        self.assertEqual(result["naive_timestamp"]["candidate_order_count"], 1)
        self.assertEqual(result["naive_timestamp"]["discarded_order_count"], 1)
        self.assertEqual(
            len({event["clock_domain"] for event in result["projected_pair"]["events"]}),
            2,
        )
        self.assertEqual(result["integrity"]["content_sha256"], content_sha256(result))

    def test_case_study_is_deterministic_and_claim_bounded(self):
        first = build_case_study(ROOT)
        second = build_case_study(ROOT)
        self.assertEqual(first, second)
        self.assertIn("does not establish a vulnerability", first["claim_boundary"])

        tampered = copy.deepcopy(first)
        tampered["naive_timestamp"]["discarded_order_count"] = 0
        self.assertNotEqual(
            tampered["integrity"]["content_sha256"], content_sha256(tampered)
        )


if __name__ == "__main__":
    unittest.main()

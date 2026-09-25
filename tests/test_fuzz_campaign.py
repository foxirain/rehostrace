import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))
sys.path.insert(0, str(ROOT / "tools"))

from rehostrace import CoverageGuidedFuzzer, validate_fuzz_policy  # noqa: E402
from run_public_fuzz_demo import public_parser  # noqa: E402


class FuzzCampaignTests(unittest.TestCase):
    def policy(self):
        return json.loads((ROOT / "fixtures/fuzz/public_parser.policy.json").read_text())

    def test_campaign_is_deterministic_and_finds_seeded_oracle(self):
        first = CoverageGuidedFuzzer(self.policy(), public_parser).run()
        second = CoverageGuidedFuzzer(self.policy(), public_parser).run()
        self.assertEqual(first, second)
        self.assertEqual(first["findings"][0]["kind"], "crash")
        self.assertIn("seeded-fault-edge", first["features"])

    def test_policy_rejects_unbounded_execution_count(self):
        policy = copy.deepcopy(self.policy())
        policy["limits"]["executions"] = 1_000_001
        with self.assertRaisesRegex(ValueError, "executions"):
            validate_fuzz_policy(policy)


if __name__ == "__main__":
    unittest.main()

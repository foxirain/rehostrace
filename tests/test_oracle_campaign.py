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
    summarize_oracle_campaign,
    validate_oracle_campaign_policy,
    wilson_interval,
)


class OracleCampaignTests(unittest.TestCase):
    def policy(self):
        return json.loads(
            (ROOT / "fixtures/platform/target_owned_reclaim.campaign.json").read_text()
        )

    def trials(self):
        return [
            json.loads(line)
            for line in (
                ROOT / "fixtures/platform/target_owned_reclaim.campaign.runs.jsonl"
            )
            .read_text()
            .splitlines()
            if line.strip()
        ]

    def test_public_campaign_preserves_three_verdicts_and_uncertainty(self):
        validation = validate_oracle_campaign_policy(self.policy())
        result = summarize_oracle_campaign(self.policy(), self.trials())
        self.assertEqual(validation["expected_runs"], 5)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(
            result["outcomes"],
            {"positive": 3, "negative": 1, "inconclusive": 1},
        )
        self.assertEqual(result["positive_rate"], 0.6)
        self.assertEqual(result["positive_rate_wilson_95"], wilson_interval(3, 5))
        self.assertEqual(result["artifact_identity_variants"], 1)
        self.assertEqual(result["effort"]["all_runs"]["median"], 7)
        self.assertEqual(result["effort"]["positive_runs"]["maximum"], 7)
        self.assertEqual(result["tag_counts"]["outcome.target-owned"], 3)

    def test_artifact_drift_is_a_hard_failure(self):
        trials = self.trials()
        trials[-1]["artifacts"]["target"] = "d" * 64
        result = summarize_oracle_campaign(self.policy(), trials)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["artifact_identity_constant"])
        self.assertEqual(result["artifact_identity_variants"], 2)

    def test_missing_run_is_inconclusive(self):
        result = summarize_oracle_campaign(self.policy(), self.trials()[:-1])
        self.assertEqual(result["status"], "inconclusive")
        self.assertFalse(result["checks"]["expected_runs_observed"])

    def test_empty_campaign_is_inconclusive_not_artifact_drift(self):
        result = summarize_oracle_campaign(self.policy(), [])
        self.assertEqual(result["status"], "inconclusive")
        self.assertTrue(result["checks"]["artifact_identity_constant"])
        self.assertEqual(result["artifact_identity_variants"], 0)

    def test_unmet_positive_threshold_is_inconclusive(self):
        policy = self.policy()
        policy["minimum_positive_runs"] = 4
        result = summarize_oracle_campaign(policy, self.trials())
        self.assertEqual(result["status"], "inconclusive")
        self.assertFalse(result["checks"]["minimum_positive_runs_met"])

    def test_duplicate_run_id_is_rejected(self):
        trials = self.trials()
        trials[-1]["run_id"] = trials[0]["run_id"]
        with self.assertRaisesRegex(ValueError, "run ids must be unique"):
            summarize_oracle_campaign(self.policy(), trials)

    def test_positive_with_failed_check_is_rejected(self):
        trials = self.trials()
        trials[0]["oracle_result"]["checks"]["contract"] = False
        with self.assertRaisesRegex(ValueError, "positive trial contains a failed check"):
            summarize_oracle_campaign(self.policy(), trials)

    def test_undeclared_tag_is_rejected(self):
        trials = self.trials()
        trials[0]["tags"].append("outcome.secret")
        with self.assertRaisesRegex(ValueError, "undeclared tags"):
            summarize_oracle_campaign(self.policy(), trials)

    def test_reclaim_oracle_output_is_accepted_directly(self):
        oracle = json.loads(
            (ROOT / "fixtures/platform/target_owned_reclaim.oracle.json").read_text()
        )
        observations = [
            json.loads(line)
            for line in (
                ROOT / "fixtures/platform/target_owned_reclaim.observations.jsonl"
            )
            .read_text()
            .splitlines()
            if line.strip()
        ]
        result = evaluate_reclaim_oracle(oracle, observations)
        policy = copy.deepcopy(self.policy())
        policy["expected_runs"] = 1
        trial = self.trials()[0]
        trial["oracle_result"] = result
        campaign = summarize_oracle_campaign(policy, [trial])
        self.assertEqual(campaign["status"], "passed")
        self.assertEqual(campaign["outcomes"]["positive"], 1)

    def test_cli_summarizes_campaign(self):
        completed = subprocess.run(
            [
                sys.executable,
                "tools/rehostrace_cli.py",
                "summarize-oracle-campaign",
                "fixtures/platform/target_owned_reclaim.campaign.json",
                "fixtures/platform/target_owned_reclaim.campaign.runs.jsonl",
            ],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["outcomes"]["inconclusive"], 1)

    def test_demo_writes_campaign_result(self):
        subprocess.run(
            [sys.executable, "tools/run_oracle_campaign_demo.py"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        result = json.loads(
            (ROOT / "out/oracle_campaign/campaign-result.json").read_text()
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["observed_runs"], 5)


if __name__ == "__main__":
    unittest.main()

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (
    compile_observer_calibration,
    validate_observer_calibration,
    validate_observer_calibration_policy,
)


class ObserverCalibrationContractTests(unittest.TestCase):
    def policy(self, *, max_error=0.05):
        return {
            "schema_version": "rehostrace.observer-calibration-policy/v1",
            "calibration_id": "public.observer.heldout-v1",
            "sources": {
                "training_report_sha256": "a" * 64,
                "holdout_report_sha256": "b" * 64,
            },
            "design": {
                "model": "multiplicative-relative-risk",
                "retrospective": False,
                "pre_registered": True,
                "training_design": "Independent observer-on/off training campaigns.",
                "holdout_design": "A distinct observer-on/off held-out campaign pair.",
                "confidence_z": 1.96,
            },
            "acceptance": {
                "max_absolute_error": max_error,
                "require_actual_within_interval": True,
                "require_disjoint_campaigns": True,
            },
            "claim_boundary": (
                "This synthetic calibration measures fixture observer effects only."
            ),
        }

    @staticmethod
    def arm(runs, violations, campaign):
        return {
            "runs": runs,
            "violations": violations,
            "clean": runs - violations,
            "rate": violations / runs,
            "campaign": {"sha256": campaign * 64},
            "identity": ["f" * 64],
            "checks": {"receipt_rehashed": True, "identity_stable": True},
        }

    def reports(self, *, holdout_off_violations=30):
        training = {
            "status": "passed",
            "observed": self.arm(100, 10, "1"),
            "unobserved": self.arm(100, 20, "2"),
        }
        holdout = {
            "status": "passed",
            "observed": self.arm(100, 15, "3"),
            "unobserved": self.arm(100, holdout_off_violations, "4"),
        }
        return training, holdout

    def compile(self, *, policy=None, holdout_off_violations=30):
        policy = policy or self.policy()
        training, holdout = self.reports(
            holdout_off_violations=holdout_off_violations
        )
        return compile_observer_calibration(
            policy,
            training,
            holdout,
            training_report_sha256=policy["sources"]["training_report_sha256"],
            holdout_report_sha256=policy["sources"]["holdout_report_sha256"],
        )

    def test_policy_validation_is_deterministic(self):
        first = validate_observer_calibration_policy(self.policy())
        second = validate_observer_calibration_policy(copy.deepcopy(self.policy()))
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "passed")

    def test_heldout_calibration_passes_and_recomputes_every_derived_value(self):
        result = self.compile()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["training"]["estimated_relative_risk"], 2.0)
        self.assertEqual(result["holdout"]["predicted_unobserved_rate"], 0.3)
        self.assertEqual(result["holdout"]["absolute_error"], 0.0)
        validation = validate_observer_calibration(result)
        self.assertEqual(validation["content_sha256"], result["integrity"]["content_sha256"])

    def test_acceptance_failure_is_a_valid_failed_result(self):
        result = self.compile(holdout_off_violations=60)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["absolute_error_within_policy"])
        self.assertEqual(validate_observer_calibration(result)["status"], "failed")

    def test_source_hash_drift_is_rejected(self):
        policy = self.policy()
        training, holdout = self.reports()
        with self.assertRaisesRegex(ValueError, "source hash mismatch"):
            compile_observer_calibration(
                policy,
                training,
                holdout,
                training_report_sha256="c" * 64,
                holdout_report_sha256=policy["sources"]["holdout_report_sha256"],
            )

    def test_overlapping_campaigns_are_rejected(self):
        policy = self.policy()
        training, holdout = self.reports()
        holdout["observed"]["campaign"]["sha256"] = training["observed"][
            "campaign"
        ]["sha256"]
        with self.assertRaisesRegex(ValueError, "campaigns are not disjoint"):
            compile_observer_calibration(
                policy,
                training,
                holdout,
                training_report_sha256=policy["sources"]["training_report_sha256"],
                holdout_report_sha256=policy["sources"]["holdout_report_sha256"],
            )

    def test_zero_training_count_and_inconsistent_report_rate_fail_closed(self):
        policy = self.policy()
        training, holdout = self.reports()
        training["observed"] = self.arm(100, 0, "1")
        with self.assertRaisesRegex(ValueError, "non-zero training counts"):
            compile_observer_calibration(
                policy,
                training,
                holdout,
                training_report_sha256=policy["sources"]["training_report_sha256"],
                holdout_report_sha256=policy["sources"]["holdout_report_sha256"],
            )

        training, holdout = self.reports()
        training["observed"]["rate"] = 0.9
        with self.assertRaisesRegex(ValueError, "rate is inconsistent"):
            compile_observer_calibration(
                policy,
                training,
                holdout,
                training_report_sha256=policy["sources"]["training_report_sha256"],
                holdout_report_sha256=policy["sources"]["holdout_report_sha256"],
            )

    def test_policy_design_and_result_integrity_tampering_are_rejected(self):
        policy = self.policy()
        policy["design"]["retrospective"] = True
        with self.assertRaisesRegex(ValueError, "exactly one"):
            validate_observer_calibration_policy(policy)

        result = self.compile()
        result["holdout"]["predicted_unobserved_rate"] = 0.31
        with self.assertRaisesRegex(ValueError, "integrity hash mismatch"):
            validate_observer_calibration(result)


if __name__ == "__main__":
    unittest.main()

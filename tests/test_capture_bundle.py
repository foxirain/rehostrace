import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import CausalTrace, compile_capture_bundle, validate_capture_bundle  # noqa: E402


class CaptureBundleTests(unittest.TestCase):
    def bundle(self):
        return json.loads((ROOT / "fixtures/capture/public_bluetooth_capture.json").read_text())

    def test_compiler_preserves_explicit_cross_actor_causality(self):
        trace = CausalTrace(compile_capture_bundle(self.bundle()))
        self.assertTrue(trace.happens_before("e01.connected", "e02.auth"))
        self.assertTrue(trace.happens_before("e02.auth", "e03.disconnected"))

    def test_unsynchronised_timestamps_do_not_create_cross_actor_edge(self):
        bundle = self.bundle()
        bundle["records"][2]["causes"] = []
        bundle["records"][3]["causes"] = []
        trace = CausalTrace(compile_capture_bundle(bundle))
        self.assertTrue(trace.concurrent("e01.connected", "e02.auth"))

    def test_unknown_explicit_cause_is_rejected(self):
        bundle = copy.deepcopy(self.bundle())
        bundle["records"][2]["causes"] = ["missing"]
        with self.assertRaisesRegex(ValueError, "causes"):
            validate_capture_bundle(bundle)


if __name__ == "__main__":
    unittest.main()

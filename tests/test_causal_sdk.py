import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import CaptureSession, CausalTrace, RecordingAdapter, ReplayEngine, ReplayError


class CausalSdkTests(unittest.TestCase):
    def fixture(self):
        return json.loads((ROOT / "fixtures/platform/async_boundary.causal.json").read_text())

    def test_public_boundary_trace_preserves_competing_branches(self):
        trace = CausalTrace(self.fixture())
        self.assertTrue(trace.happens_before("e.timeout", "e.tx-disconnect"))
        self.assertTrue(trace.happens_before("e.link-loss-irq", "e.reset-run"))
        self.assertTrue(trace.concurrent("e.tx-disconnect", "e.link-loss-irq"))
        self.assertTrue(trace.concurrent("e.tx-disconnect", "e.reset-run"))

    def test_canonical_digest_ignores_document_list_order(self):
        original = CausalTrace(self.fixture())
        permuted_document = self.fixture()
        permuted_document["actors"].reverse()
        permuted_document["resources"].reverse()
        permuted_document["events"].reverse()
        permuted = CausalTrace(permuted_document)
        self.assertEqual(original.digest, permuted.digest)

    def test_cycle_is_rejected_even_when_parent_appears_later(self):
        trace = self.fixture()
        trace["events"][0]["parents"] = ["e.reset-run"]
        with self.assertRaisesRegex(ValueError, "cycle"):
            CausalTrace(trace)

    def test_replay_rejects_non_linear_extension(self):
        trace = CausalTrace(self.fixture())
        order = list(trace.validation["topological_order"])
        order.remove("e.session-ready")
        order.insert(1, "e.session-ready")
        with self.assertRaisesRegex(ReplayError, "not ready"):
            ReplayEngine(trace, RecordingAdapter()).run(order)

    def test_capture_chains_only_actor_program_order_by_default(self):
        capture = CaptureSession(
            "public.capture.test", "public-synthetic", "synthetic", "unit-test"
        )
        capture.add_actor("actor.a", "thread")
        capture.add_actor("actor.b", "interrupt")
        capture.add_resource("object.1", "object", "logical")
        capture.emit(
            "event.a1",
            "actor.a",
            "custom",
            "unit",
            "a1",
            "internal",
            subject="object.1",
        )
        capture.emit(
            "event.b1",
            "actor.b",
            "interrupt",
            "unit",
            "b1",
            "target-in",
            subject="object.1",
        )
        capture.emit(
            "event.a2",
            "actor.a",
            "custom",
            "unit",
            "a2",
            "internal",
            subject="object.1",
        )
        trace = CausalTrace(capture.finish())
        self.assertTrue(trace.happens_before("event.a1", "event.a2"))
        self.assertTrue(trace.concurrent("event.b1", "event.a2"))

    def test_redacted_capture_rejects_inline_payload(self):
        capture = CaptureSession(
            "public.capture.redacted", "public-redacted", "live-capture", "unit-test"
        )
        capture.add_actor("actor.a", "host")
        with self.assertRaisesRegex(ValueError, "cannot inline"):
            capture.emit(
                "event.a",
                "actor.a",
                "boundary.input",
                "unit",
                "input",
                "target-in",
                payload=CaptureSession.payload(b"secret", include=True),
            )

    def test_inline_payload_digest_is_verified(self):
        capture = CaptureSession(
            "public.capture.payload", "public-synthetic", "synthetic", "unit-test"
        )
        capture.add_actor("actor.a", "host")
        payload = CaptureSession.payload(b"boundary", include=True, encoding="hex")
        payload["data"] = "00"
        capture.emit(
            "event.a",
            "actor.a",
            "boundary.input",
            "unit",
            "input",
            "target-in",
            payload=payload,
        )
        with self.assertRaisesRegex(ValueError, "payload length mismatch"):
            capture.finish()


if __name__ == "__main__":
    unittest.main()

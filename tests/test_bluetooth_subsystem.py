import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (  # noqa: E402
    BluetoothCoreAdapter,
    BluetoothStateError,
    CausalTrace,
    ReplayEngine,
    default_bluetooth_registrations,
    validate_protocol_pack,
)


class BluetoothSubsystemTests(unittest.TestCase):
    pack_names = (
        "hci_core.pack.json",
        "l2cap_core.pack.json",
        "avdtp_signaling.pack.json",
    )

    def trace_document(self):
        return json.loads(
            (ROOT / "fixtures/bluetooth/hci_l2cap_avdtp.causal.json").read_text()
        )

    def manifests(self):
        return [
            json.loads((ROOT / "fixtures/bluetooth" / name).read_text())
            for name in self.pack_names
        ]

    def run_document(self, document):
        adapter = BluetoothCoreAdapter(default_bluetooth_registrations(self.manifests()))
        replay = ReplayEngine(CausalTrace(document), adapter).run()
        return replay, adapter.summary()

    def event(self, document, event_id):
        return next(event for event in document["events"] if event["id"] == event_id)

    def test_public_multilayer_trace_reaches_clean_terminal_state(self):
        replay, summary = self.run_document(self.trace_document())
        self.assertEqual(replay["status"], "passed")
        self.assertEqual(summary["event_count"], 31)
        self.assertEqual(summary["connections"]["0x0040"]["state"], "disconnected")
        self.assertEqual(summary["channels"]["0x0040/0x0040"]["state"], "closed")
        self.assertEqual(summary["avdtp_sessions"]["0x0040/0x0040"]["state"], "discovered")

    def test_acl_continuation_without_complete_reassembly_is_rejected(self):
        document = self.trace_document()
        start = self.event(document, "e06.conn-req-fragment-start")
        start["attributes"]["packet_boundary"] = "complete"
        with self.assertRaisesRegex(BluetoothStateError, "complete ACL packet"):
            self.run_document(document)

    def test_unknown_connection_handle_is_rejected_before_l2cap(self):
        document = self.trace_document()
        self.event(document, "e09.pending-acl")["attributes"]["handle"] = 65
        with self.assertRaisesRegex(BluetoothStateError, "unknown or disconnected HCI handle"):
            self.run_document(document)

    def test_avdtp_transaction_label_mismatch_is_rejected(self):
        document = self.trace_document()
        self.event(document, "e25.avdtp-accept")["attributes"]["transaction_label"] = 2
        with self.assertRaisesRegex(BluetoothStateError, "does not match"):
            self.run_document(document)

    def test_l2cap_config_response_without_request_is_rejected(self):
        document = self.trace_document()
        self.event(document, "e16.local-config-response")["attributes"]["initiator"] = "peer"
        with self.assertRaisesRegex(BluetoothStateError, "no matching request"):
            self.run_document(document)

    def test_hci_command_credit_is_enforced(self):
        document = self.trace_document()
        self.event(document, "e00.controller-ready")["attributes"]["command_credits"] = 0
        with self.assertRaisesRegex(BluetoothStateError, "no controller credit"):
            self.run_document(document)

    def test_manifest_handler_operation_drift_is_rejected(self):
        manifests = self.manifests()
        changed = copy.deepcopy(manifests[0])
        changed["selectors"] = changed["selectors"][:-1]
        with self.assertRaisesRegex(ValueError, "operation drift"):
            BluetoothCoreAdapter(default_bluetooth_registrations([changed, *manifests[1:]]))

    def test_manifest_validation_is_canonical_and_data_only(self):
        result = validate_protocol_pack(self.manifests()[2])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["protocol"], "avdtp")
        self.assertEqual(len(result["canonical_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()

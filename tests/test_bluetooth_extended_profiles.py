import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (  # noqa: E402
    BluetoothCoreAdapter,
    BluetoothPackRegistry,
    BluetoothStateError,
    CausalTrace,
    ReplayEngine,
    built_in_bluetooth_registry,
    default_bluetooth_registrations,
)


class BluetoothExtendedProfileTests(unittest.TestCase):
    fixture_dir = ROOT / "fixtures/bluetooth"

    def read(self, name):
        return json.loads((self.fixture_dir / name).read_text())

    def replay(self, trace_name, pack_names):
        trace = CausalTrace(self.read(trace_name))
        manifests = [self.read(name) for name in pack_names]
        adapter = BluetoothCoreAdapter(default_bluetooth_registrations(manifests))
        replay = ReplayEngine(trace, adapter).run()
        return replay, adapter.summary()

    def test_all_extended_lifecycle_fixtures_finish_cleanly(self):
        cases = [
            ("smp_pairing.causal.json", ["hci_core.pack.json", "smp.pack.json"], "completed_pairings"),
            ("rfcomm_hfp.causal.json", ["hci_core.pack.json", "rfcomm.pack.json", "hfp.pack.json"], "completed_sessions"),
            ("avrcp_a2dp.causal.json", ["hci_core.pack.json", "avrcp.pack.json", "a2dp.pack.json"], "completed_streams"),
            ("le_audio_iso.causal.json", ["hci_core.pack.json", "le_audio.pack.json"], "completed_groups"),
        ]
        for trace_name, packs, terminal_key in cases:
            with self.subTest(trace=trace_name):
                replay, summary = self.replay(trace_name, packs)
                self.assertEqual(replay["status"], "passed")
                extension_values = summary["extensions"].values()
                self.assertTrue(any(terminal_key in value for value in extension_values))

    def test_smp_rejects_completion_before_random_exchange(self):
        trace = self.read("smp_pairing.causal.json")
        trace["events"] = [event for event in trace["events"] if event["id"] != "e06.peer-random"]
        next(event for event in trace["events"] if event["id"] == "e07.complete")["parents"] = ["e05.local-random"]
        adapter = BluetoothCoreAdapter(default_bluetooth_registrations([self.read("hci_core.pack.json"), self.read("smp.pack.json")]))
        with self.assertRaisesRegex(BluetoothStateError, "confirm/random"):
            ReplayEngine(CausalTrace(trace), adapter).run()

    def test_a2dp_rejects_media_before_stream_start(self):
        trace = self.read("avrcp_a2dp.causal.json")
        media = next(event for event in trace["events"] if event["id"] == "e05.media")
        media["parents"] = ["e03.open"]
        start = next(event for event in trace["events"] if event["id"] == "e04.start")
        start["parents"] = ["e05.media"]
        adapter = BluetoothCoreAdapter(default_bluetooth_registrations([
            self.read("hci_core.pack.json"), self.read("avrcp.pack.json"), self.read("a2dp.pack.json")
        ]))
        with self.assertRaisesRegex(BluetoothStateError, "not running"):
            ReplayEngine(CausalTrace(trace), adapter).run()

    def test_registry_rejects_untrusted_manifest_handler(self):
        manifest = copy.deepcopy(self.read("smp.pack.json"))
        manifest["pack_id"] = "public.bluetooth.untrusted.v1"
        registry = built_in_bluetooth_registry()
        with self.assertRaisesRegex(ValueError, "no registered handler"):
            registry.resolve([manifest])
        self.assertIsInstance(BluetoothPackRegistry(), BluetoothPackRegistry)


if __name__ == "__main__":
    unittest.main()

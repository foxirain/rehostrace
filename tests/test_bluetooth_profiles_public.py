import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import (  # noqa: E402
    BluetoothCoreAdapter,
    CausalTrace,
    ReplayEngine,
    default_bluetooth_registrations,
    validate_profile_catalog,
)


class PublicBluetoothProfileTests(unittest.TestCase):
    def test_all_catalog_profiles_replay_without_target_adapter(self):
        fixture_dir = ROOT / "fixtures/bluetooth"
        catalog = validate_profile_catalog(
            json.loads((fixture_dir / "profile_catalog.json").read_text(encoding="utf-8"))
        )
        total_events = 0
        machines = set()
        transports = set()
        for profile in catalog["profiles"]:
            trace = CausalTrace(
                json.loads((fixture_dir / profile["trace"]).read_text(encoding="utf-8"))
            )
            manifests = [
                json.loads((fixture_dir / name).read_text(encoding="utf-8"))
                for name in profile["packs"]
            ]
            adapter = BluetoothCoreAdapter(default_bluetooth_registrations(manifests))
            replay = ReplayEngine(trace, adapter).run()
            self.assertEqual(replay["status"], "passed", profile["id"])
            self.assertEqual(adapter.summary()["event_count"], len(trace.events))
            total_events += len(trace.events)
            machines.update(profile["state_machines"])
            transports.add(profile["transport"])
        self.assertEqual(len(catalog["profiles"]), 7)
        self.assertGreater(total_events, 60)
        self.assertEqual(transports, {"BR/EDR ACL", "LE ACL", "LE ISO"})
        self.assertTrue(
            {
                "AVDTP",
                "SDP",
                "ATT",
                "GATT",
                "SMP",
                "RFCOMM",
                "HFP",
                "AVRCP",
                "A2DP",
                "LE Audio",
            }.issubset(machines)
        )


if __name__ == "__main__":
    unittest.main()

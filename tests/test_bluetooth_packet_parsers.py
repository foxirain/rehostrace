import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk/python"))

from rehostrace import PacketParseError, built_in_packet_parser_registry  # noqa: E402


class BluetoothPacketParserTests(unittest.TestCase):
    def setUp(self):
        self.registry = built_in_packet_parser_registry()

    def test_registry_has_six_requested_parser_families(self):
        self.assertEqual(self.registry.protocols, ("a2dp-rtp", "avrcp", "hfp-at", "le-iso", "rfcomm", "smp"))

    def test_representative_packets_parse(self):
        packets = {
            "smp": bytes.fromhex("01030001100707"),
            "rfcomm": bytes.fromhex("03ef0142"),
            "avrcp": bytes.fromhex("00110e00487c"),
            "hfp-at": b"AT+BRSF=20\r",
            "a2dp-rtp": bytes.fromhex("806000010000000100000002aa"),
            "le-iso": bytes.fromhex("0100050001000100aa"),
        }
        for protocol, packet in packets.items():
            with self.subTest(protocol=protocol):
                parsed = self.registry.parse(protocol, packet)
                self.assertTrue(parsed.features)
                self.assertTrue(parsed.fields)

    def test_declared_lengths_fail_closed(self):
        malformed = {
            "smp": bytes.fromhex("0300"),
            "rfcomm": bytes.fromhex("03ef0342"),
            "avrcp": bytes.fromhex("04110e00487c"),
            "hfp-at": b"not-at\r",
            "a2dp-rtp": bytes.fromhex("006000010000000100000002aa"),
            "le-iso": bytes.fromhex("0100060001000100aa"),
        }
        for protocol, packet in malformed.items():
            with self.subTest(protocol=protocol):
                with self.assertRaises(PacketParseError):
                    self.registry.parse(protocol, packet)

    def test_unregistered_parser_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no trusted parser"):
            self.registry.parse("unknown", b"")


if __name__ == "__main__":
    unittest.main()

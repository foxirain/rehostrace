import stat
import struct
import tempfile
import unittest
from pathlib import Path

from tools.build_newc import TRAILER, build_archive


def parse_newc(blob: bytes):
    offset = 0
    entries = []
    while True:
        header = blob[offset : offset + 110]
        if header[:6] != b"070701":
            raise AssertionError(f"bad magic at {offset}")
        fields = [int(header[6 + i * 8 : 14 + i * 8], 16) for i in range(13)]
        mode, size, namesize = fields[1], fields[6], fields[11]
        offset += 110
        name = blob[offset : offset + namesize - 1].decode()
        offset += namesize
        offset += (-offset) & 3
        data = blob[offset : offset + size]
        offset += size
        offset += (-offset) & 3
        entries.append((name, mode, data))
        if name == TRAILER:
            return entries


class NewcTests(unittest.TestCase):
    def test_archive_is_deterministic_and_preserves_executable_bit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "modules").mkdir()
            init = root / "init"
            init.write_bytes(b"ELF")
            init.chmod(0o755)
            (root / "modules" / "one.ko").write_bytes(b"module")
            first = build_archive(root)
            second = build_archive(root)
            self.assertEqual(first, second)
            entries = {name: (mode, data) for name, mode, data in parse_newc(first)}
            self.assertEqual(entries["init"], (stat.S_IFREG | 0o755, b"ELF"))
            self.assertEqual(entries["modules/one.ko"], (stat.S_IFREG | 0o644, b"module"))
            self.assertIn(TRAILER, entries)


if __name__ == "__main__":
    unittest.main()

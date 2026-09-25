import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BluetoothParserFuzzTests(unittest.TestCase):
    def test_all_six_parser_campaigns_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, str(ROOT / "tools/run_bluetooth_parser_fuzz_demo.py"), "--output", directory],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            result = json.loads(completed.stdout.splitlines()[-1])
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["campaigns"], 6)
            self.assertGreater(result["executions"], 0)


if __name__ == "__main__":
    unittest.main()

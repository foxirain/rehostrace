import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "audit_framework_release", ROOT / "tools/audit_framework_release.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ReleaseAuditTests(unittest.TestCase):
    def populate_required(self, root: Path) -> None:
        for name in MODULE.REQUIRED:
            (root / name).write_text("public fixture\n", encoding="utf-8")

    def test_current_tree_passes(self):
        report = MODULE.audit(ROOT)
        self.assertEqual(report["status"], "passed", report["errors"])

    def test_target_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate_required(root)
            marker = bytes.fromhex("73616d73756e67").decode("ascii")
            (root / "notes.md").write_text(marker, encoding="utf-8")
            report = MODULE.audit(root)
            self.assertEqual(report["status"], "failed")
            self.assertIn("target-or-host-marker", {error["kind"] for error in report["errors"]})

    def test_generated_module_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate_required(root)
            (root / "fixture.ko").write_bytes(b"not a release source")
            report = MODULE.audit(root)
            self.assertEqual(report["status"], "failed")
            self.assertIn(
                "generated-or-binary-artifact",
                {error["kind"] for error in report["errors"]},
            )


if __name__ == "__main__":
    unittest.main()

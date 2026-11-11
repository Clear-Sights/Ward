"""The register map is bound to the suite.

A rule written and left to be run by hand is register entry B7, so this test is
the binding. It asserts both directions -- green as the tree stands, red on a
planted gap -- because a runner that has stopped deciding looks like one that
agrees.
"""
from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


# Digest of docs/REGISTER.md, this repository's own copy (its former source,
# measure-zero-dev/REGISTER.md, is not among the owner's repositories; byte-identical
# to Clear-Sights/Keel docs/REGISTER.md). Re-pin deliberately when the register changes; that edit is the
# record that it moved.
REGISTER_DIGEST = "f262b53bcb839927ec045402522cff1ba64b6e9665cadf0d4734c858fd71ee69"


class RegisterMapIsBound(unittest.TestCase):
    """unittest classes, not bare pytest functions: CI runs `unittest discover`, which
    collects only TestCase methods, so bare functions here were never run in CI."""

    def test_register_map_is_green_and_every_table_row_is_cited(self):
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "register_map.py")],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("every entry carried", r.stdout)
        self.assertIn("table rows cited 11 of 11", r.stdout)

    def _main_with_map(self, transform):
        import register_map

        lines = register_map.MAP.read_text(encoding="utf-8").splitlines()
        with tempfile.TemporaryDirectory() as tmp:
            planted = pathlib.Path(tmp) / "REGISTER-MAP.tsv"
            planted.write_text(transform(lines), encoding="utf-8")
            with mock.patch.object(register_map, "MAP", planted):
                return register_map.main()

    def test_register_map_reddens_on_an_entry_with_no_row(self):
        code = self._main_with_map(
            lambda lines: "\n".join(ln for ln in lines if not ln.startswith("C10\t")) + "\n")
        self.assertEqual(code, 2)

    def test_register_map_reddens_on_a_row_the_table_does_not_carry(self):
        code = self._main_with_map(
            lambda lines: "\n".join(ln.replace("\tward.jwt_none_alg\t", "\tward.no_such_row\t")
                                    for ln in lines) + "\n")
        self.assertEqual(code, 2)

    def test_vendored_register_matches_its_pinned_digest(self):
        """docs/REGISTER.md is a copy, and this fence pins it.

        Two copies of one rule is register entry F2. The fence compares the copy
        against its own pinned digest, never against the owner's live tree: a check
        that reads another repository only evaluates where that repository happens
        to sit, which is entry E7. This one evaluates everywhere.
        """
        actual = hashlib.sha256((ROOT / "docs" / "REGISTER.md").read_bytes()).hexdigest()
        self.assertEqual(actual, REGISTER_DIGEST,
                         "docs/REGISTER.md moved without its pin being updated; re-vendor and re-pin")


if __name__ == "__main__":
    unittest.main()

"""Repository-local citations are claims that must resolve in this checkout."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ward.citations import dangling_relative_references, relative_references


REPO = Path(__file__).resolve().parent.parent


class CitationResolution(unittest.TestCase):
    def test_every_relative_documentation_and_manifest_reference_resolves(self) -> None:
        dangling = dangling_relative_references(REPO)
        self.assertEqual(
            [],
            dangling,
            "unresolved repository-local reference(s): "
            + "; ".join(reference.display(REPO) for reference in dangling),
        )

    def test_broken_relative_reference_is_detected(self) -> None:
        """Control: a citation checker that cannot reject this fixture has no teeth."""
        with tempfile.TemporaryDirectory(prefix="ward-citation-fixture-") as temporary:
            root = Path(temporary)
            (root / "README.md").write_text(
                "[missing](NOT-THERE.md), [extensionless](NO-EXTENSION), "
                "and `also-missing.py`\n", encoding="utf-8")
            references = relative_references(root)
            self.assertEqual(["NOT-THERE.md", "NO-EXTENSION", "also-missing.py"],
                             [reference.target for reference in references])
            self.assertEqual(references, dangling_relative_references(root))

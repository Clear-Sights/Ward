"""Checks for repository artifacts that must not ship as dead development residue."""
from pathlib import Path
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parent.parent
# What a user actually installs. Everything outside it -- tests, eval, tools -- stays here.
PLUGIN = REPO / "plugin"


class ImportProvenance(unittest.TestCase):
    """Whether a green run is evidence about THIS tree."""

    def test_the_package_under_test_came_from_this_checkout(self):
        """A bare `python3 -m unittest discover -s tests` here imported `ward` from a DIFFERENT
        repository: a stale `__editable__.ward-0.1.0.pth` in dist-packages resolves the name to
        another tree, so the suite graded code this branch does not contain and still reported OK.

        Measured, not supposed: neutering `forbidden_location` to `return None` in THIS tree left
        the run at `Ran 113 tests OK`, because the bytes under test came from elsewhere. The same
        plant against the tree actually imported turned it red with 8 failures. Nothing recorded
        which tree was read, so the wrong answer was shaped exactly like the right one.

        CI installs this checkout (`pip install -e .`) and satisfies this. A local run that does
        not now fails by name instead of silently grading another repository's code."""
        import ward
        origin = Path(ward.__file__).resolve()
        self.assertTrue(
            origin.is_relative_to(PLUGIN),
            f"tests import ward from {origin}, which is outside {PLUGIN}: this run grades a "
            f"different tree. Re-run with PYTHONPATH={PLUGIN}, or remove the stale editable install",
        )


class RepositoryHygiene(unittest.TestCase):
    def test_path_resolution_report_is_not_shipped(self):
        report = REPO / "out-ward-pathresolve.md"
        self.assertFalse(
            report.exists(),
            "remove the unreferenced path-resolution development report before shipping",
        )

    def test_no_render_scratch_directories_are_tracked(self):
        """render_readme_images.py works in a mkdtemp under docs/img; a committed one ships a
        whole headless-Chromium profile (History, Web Data, Login Data databases) as repository
        content. Three such directories were found tracked and removed; this pins the removal."""
        from tools.render_readme_images import IMAGE_DIR
        self.assertTrue(IMAGE_DIR.is_dir(), f"the renderer image directory is missing: {IMAGE_DIR}")
        strays = [str(path.relative_to(REPO)) for path in IMAGE_DIR.rglob("*")
                  if ".ward-readme-images-" in path.name]
        self.assertEqual(strays, [], "render scratch directories are tracked: remove them")

    def test_security_guide_uses_the_supported_stdlib_test_command(self):
        guide = (REPO / "SECURITY.md").read_text(encoding="utf-8")
        documented_command = "$ python -m unittest discover -s tests -p 'test_path_reliability.py'"
        self.assertNotIn("pytest", guide.lower())
        self.assertIn(documented_command, guide)


class ManifestsAgreeWithTheTree(unittest.TestCase):
    """Keep hook, package, and marketplace declarations synchronized with the shipped tree."""

    def test_every_hook_command_resolves_to_an_executable_file(self) -> None:
        manifest = json.loads((PLUGIN / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        commands = [
            entry["command"]
            for group in manifest["hooks"].values()
            for matcher in group
            for entry in matcher["hooks"]
            if entry.get("type") == "command"
        ]
        self.assertTrue(commands, "hooks.json declares no commands -- the hook is wired to nothing")
        for command in commands:
            target = PLUGIN / command.replace("${CLAUDE_PLUGIN_ROOT}/", "")
            self.assertTrue(target.is_file(), f"hooks.json names {command!r}, not in the tree")
            self.assertTrue(os.access(target, os.X_OK), f"{command!r} is not executable")

    def test_the_two_version_declarations_agree(self) -> None:
        plugin = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        declared = re.search(r'^version\s*=\s*"([^"]+)"',
                             (REPO / "pyproject.toml").read_text(encoding="utf-8"), re.MULTILINE)
        self.assertIsNotNone(declared, "pyproject.toml declares no version")
        self.assertEqual(
            plugin["version"], declared.group(1),
            f"two version declarations for one product disagree: plugin.json says "
            f"{plugin['version']}, pyproject.toml says {declared.group(1)}",
        )

    def test_the_marketplace_entry_names_this_plugin(self) -> None:
        """A marketplace listing pointing at a plugin name that does not exist installs nothing."""
        marketplace = json.loads(
            (REPO / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
        plugin = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        entries = [entry for entry in marketplace.get("plugins", [])
                   if entry.get("name") == plugin["name"]]
        self.assertEqual(len(entries), 1,
                         f"marketplace.json must list plugin {plugin['name']!r} exactly once")
        # `./plugin`, not `./`. The source is the subtree a user receives, and sourcing the
        # repository root shipped `tests/`, `eval/` and `tools/` to every installing machine.
        # Asserted against the directory that must actually hold the manifest, so a source that
        # drifts back to the root cannot pass by naming a plugin.json that is no longer there.
        self.assertEqual(entries[0].get("source"), "./plugin",
                         f"marketplace entry for {plugin['name']!r} must source the plugin subtree")
        self.assertTrue((REPO / "plugin" / ".claude-plugin" / "plugin.json").is_file(),
                        "the sourced subtree must be the one carrying plugin.json")


class MeasurementProvenance(unittest.TestCase):
    """Whether a rendered README number is evidence about THIS tree.

    `ImportProvenance` above settles the suite's own imports. It says nothing about the
    measurement tools, which reach the code a second way: `tools/measure.py` and
    `tools/render_readme_claims.py` SPAWN the suite and the replay as subprocesses. Those
    children inherited the caller's environment unpinned, so `import ward` inside them resolved
    to whatever `ward` that environment held -- an installed sibling package, a stale editable
    `.pth`, another checkout -- and the count that came back was rendered into README.md as this
    repository's evidence while describing other bytes. With no `ward` importable at all the same
    omission surfaced only as `RuntimeError: unit suite did not produce a passing test count`,
    which names the symptom and not the cause.

    This grades the pin rather than the tools' happy path: a decoy `ward` package is placed FIRST
    on `PYTHONPATH` and the measurement must still report this checkout's numbers. Prepending is
    what is being asserted -- a merely appended `plugin/` would fill in for an absent `ward` and
    still lose to the decoy, passing a weaker check that reads the same. Witnessed, not assumed:
    with `child_env` appending instead of prepending, this class reports `FAILED (errors=1)`.

    ONE cell, not two, and the missing one is stated rather than quietly dropped. Only the suite
    measurement was ever exposed: `eval/replay.py` spawns `python -m ward.dispatch` with
    `cwd=plugin/`, so the current directory already resolves `ward` to this checkout ahead of any
    inherited `PYTHONPATH`, and a decoy cannot reach it. A replay cell here would have passed
    against the pinned AND the unpinned tool -- a check that cannot fail is not evidence, so it
    is not shipped. `render_readme_claims.py` still passes `child_env()` to that subprocess for
    uniformity; that is defence in depth, not a defect closed.
    """

    def setUp(self):
        # A measurement spawns the suite and the suite calls a measurement. `measure.child_env`
        # sets this marker in every child, which bounds that nesting at depth one. The cell is
        # not weakened by it: the ordinary top-level run has no marker and grades in full.
        if os.environ.get("WARD_MEASUREMENT_CHILD"):
            self.skipTest("already inside a spawned measurement; the top-level run grades this")

    def _decoy(self) -> str:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        package = directory / "ward"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "checks.py").write_text("CHECKS = []\ndef evaluate(event):\n    return None\n",
                                           encoding="utf-8")
        return str(directory)

    def _under_decoy(self, attribute: str):
        """Call `measure.<attribute>()` with a decoy `ward` first on the child's PYTHONPATH.

        `tools/` is put on `sys.path` here rather than at module import: the module under
        measurement is a script directory, not an installed package, and importing it at module
        scope would make this whole file unimportable wherever that directory is absent.
        """
        sys.path.insert(0, str(REPO / "tools"))
        try:
            import measure
            with mock.patch.dict(os.environ, {"PYTHONPATH": self._decoy()}):
                return getattr(measure, attribute)()
        finally:
            sys.path.remove(str(REPO / "tools"))

    def test_the_suite_count_measures_this_checkout_not_an_inherited_ward(self):
        counted = self._under_decoy("suite_count")
        # Not merely "nonzero": the decoy makes the real suite unrunnable, so the unpinned
        # failure mode is a raise, and the number is pinned to the count this tree's own
        # discovery reports rather than to any number that happens to arrive.
        self.assertEqual(counted, self._discovered(),
                         "measure.suite_count graded a ward that is not this checkout's")

    def _discovered(self) -> int:
        loaded = unittest.defaultTestLoader.discover(str(REPO / "tests"), top_level_dir=str(REPO))
        return loaded.countTestCases()

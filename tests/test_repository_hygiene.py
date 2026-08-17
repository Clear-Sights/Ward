"""Checks for repository artifacts that must not ship as dead development residue."""
from pathlib import Path
import json
import os
import re
import unittest


REPO = Path(__file__).resolve().parent.parent


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
        import subprocess
        tracked = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "docs/img"],
            capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        strays = [line for line in tracked if ".ward-readme-images-" in line]
        self.assertEqual(strays, [], "render scratch directories are tracked: remove them")

    def test_security_guide_uses_the_supported_stdlib_test_command(self):
        guide = (REPO / "SECURITY.md").read_text(encoding="utf-8")
        documented_command = "$ python -m unittest discover -s tests -p 'test_path_reliability.py'"
        self.assertNotIn("pytest", guide.lower())
        self.assertIn(documented_command, guide)


class ManifestsAgreeWithTheTree(unittest.TestCase):
    """Keep hook, package, and marketplace declarations synchronized with the shipped tree."""

    def test_every_hook_command_resolves_to_an_executable_file(self) -> None:
        manifest = json.loads((REPO / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        commands = [
            entry["command"]
            for group in manifest["hooks"].values()
            for matcher in group
            for entry in matcher["hooks"]
            if entry.get("type") == "command"
        ]
        self.assertTrue(commands, "hooks.json declares no commands -- the hook is wired to nothing")
        for command in commands:
            target = REPO / command.replace("${CLAUDE_PLUGIN_ROOT}/", "")
            self.assertTrue(target.is_file(), f"hooks.json names {command!r}, not in the tree")
            self.assertTrue(os.access(target, os.X_OK), f"{command!r} is not executable")

    def test_the_two_version_declarations_agree(self) -> None:
        plugin = json.loads((REPO / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
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
        plugin = json.loads((REPO / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        entries = [entry for entry in marketplace.get("plugins", [])
                   if entry.get("name") == plugin["name"]]
        self.assertEqual(len(entries), 1,
                         f"marketplace.json must list plugin {plugin['name']!r} exactly once")
        self.assertEqual(entries[0].get("source"), "./",
                         f"marketplace entry for {plugin['name']!r} must source this tree")

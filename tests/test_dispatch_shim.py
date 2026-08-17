"""Subprocess end-to-end for hooks/dispatch.sh — the shim itself, which every other test
bypasses. It pins the two properties only the shim owns: (1) package resolution is pinned to the
plugin root — a decoy ward/ package in the invoking cwd must not shadow it (under the former
PYTHONPATH form it did, and every check silently vanished), and (2) an unusable
CLAUDE_PLUGIN_ROOT fails CLOSED with a deny, matching ward.dispatch's own internal-error
direction — a gate whose machinery cannot start must never look like a pass. Runs against a bare
venv interpreter so a dev-tree editable install cannot mask a resolution failure — with the dev
interpreter these checks could never return FALSE."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import venv
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SHIM = REPO / "hooks" / "dispatch.sh"
HOOKS = REPO / "hooks" / "hooks.json"

FLAGGED = {"hook_event_name": "PreToolUse", "tool_name": "Write",
           "tool_input": {"file_path": "/workspace/repo/mod.py",
                          "content": "import requests\nrequests.get(u, verify=False)\n"},
           "cwd": "/workspace/repo"}


def _run_shim(event: dict | None, cwd: Path, env_overrides: dict) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_ROOT", "PYTHONPATH")}
    env.update(env_overrides)
    return subprocess.run([str(SHIM)], input=json.dumps(event or {}), text=True,
                          capture_output=True, cwd=cwd, env=env, timeout=30)


class Shim(unittest.TestCase):
    """setUpClass and a per-test TemporaryDirectory replace pytest's tmp_path_factory and
    tmp_path exactly: same lifetimes, same isolation, and nothing outside the standard library.

    The venv is built once for the class because the fixture it replaces was module-scoped.
    Building it per test would multiply a slow operation by six and buy no isolation these
    tests use — each one writes only into its own scratch directory.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls._venv = tempfile.TemporaryDirectory(prefix="ward-bare-venv-")
        env_dir = Path(cls._venv.name) / "bare-venv"
        venv.create(env_dir, with_pip=False)
        cls.bare_python_dir = env_dir / ("Scripts" if sys.platform == "win32" else "bin")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._venv.cleanup()

    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(prefix="ward-shim-")
        self.addCleanup(scratch.cleanup)
        self.tmp_path = Path(scratch.name)

    def test_shim_is_executable(self):
        assert os.access(SHIM, os.X_OK), "hooks/dispatch.sh must carry the executable bit in git"

    def test_hook_uses_exec_form_for_plugin_path(self):
        config = json.loads(HOOKS.read_text())
        handler = config["hooks"]["PreToolUse"][0]["hooks"][0]
        assert handler["command"] == "${CLAUDE_PLUGIN_ROOT}/hooks/dispatch.sh"
        assert handler["args"] == []

    def test_decoy_package_in_cwd_cannot_shadow_the_plugin(self):
        (self.tmp_path / "ward").mkdir()
        (self.tmp_path / "ward" / "__init__.py").write_text("")
        proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={
            "CLAUDE_PLUGIN_ROOT": str(REPO),
            "PATH": f"{self.bare_python_dir}{os.pathsep}{os.environ['PATH']}",
        })
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        assert out["permissionDecision"] == "deny"
        assert "verify=False" in out["permissionDecisionReason"]
        assert "ward.cert_verify_disabled" in out["permissionDecisionReason"]

    def test_unusable_plugin_root_fails_closed(self):
        proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={})  # PLUGIN_ROOT absent
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        assert out["permissionDecision"] == "deny"
        assert "failing closed" in out["permissionDecisionReason"]

    def test_existing_non_plugin_root_fails_closed(self):
        proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={
            "CLAUDE_PLUGIN_ROOT": str(self.tmp_path),
            "PATH": f"{self.bare_python_dir}{os.pathsep}{os.environ['PATH']}",
        })
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        assert out["permissionDecision"] == "deny"
        assert "failing closed" in out["permissionDecisionReason"]

    def test_malformed_hook_input_fails_closed(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("CLAUDE_PLUGIN_ROOT", "PYTHONPATH")}
        env["CLAUDE_PLUGIN_ROOT"] = str(REPO)
        proc = subprocess.run([str(SHIM)], input="{", text=True, capture_output=True,
                              cwd=self.tmp_path, env=env, timeout=30)
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        assert out["permissionDecision"] == "deny"
        assert "malformed" in out["permissionDecisionReason"]

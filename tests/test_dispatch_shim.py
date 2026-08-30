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


def _ck(cond, msg=""):
    """An assertion that survives `-O`.

    `assert` is compiled out entirely under -O/PYTHONOPTIMIZE, and this file carried 87 bare
    `assert`s and zero `self.assert*`. Verified two-sided against this checkout's own tree: with
    `ward.checks.evaluate` disarmed to `return None`, `python3 -m unittest tests.test_checks`
    reported `FAILED (failures=43)` -- but `python3 -O -m unittest tests.test_checks` reported
    `Ran 67 tests ... OK`, exit 0. Ward fully disarmed, its entire security parity suite green. A
    test that cannot fail is not evidence, so the check has to outlive the optimizer.
    """
    if not cond:
        raise AssertionError(msg or "check failed")


REPO = Path(__file__).resolve().parent.parent
# The shim cd-pins to CLAUDE_PLUGIN_ROOT, which is the installed plugin -- plugin/, not the
# repository root. Pointing the tests at the repository root would exercise a layout no user has.
PLUGIN = REPO / "plugin"
SHIM = PLUGIN / "hooks" / "dispatch.sh"
HOOKS = PLUGIN / "hooks" / "hooks.json"

FLAGGED = {"hook_event_name": "PreToolUse", "tool_name": "Write",
           "tool_input": {"file_path": "/workspace/repo/mod.py",
                          "content": "import requests\nrequests.get(u, verify=False)\n"},
           "cwd": "/workspace/repo"}


def _run_shim(event: dict | None, cwd: Path, env_overrides: dict) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_ROOT", "PYTHONPATH")}
    # The shim runs the real dispatcher, which journals every fabricated deny/fault. Keep that
    # evidence inside this test's disposable directory rather than polluting the operator's log.
    env["WARD_STATE_DIR"] = str(cwd / "ward-test-state")
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
        """The bit GIT records, not the one this checkout happens to have.

        `os.access(SHIM, os.X_OK)` reads the working tree, while the message beside it said "in
        git" -- and git's mode is what ships. A local `chmod +x` made this pass over an index
        recording 100644, and a restrictive checkout could fail it over an index that is
        correct. Neither answer was about the thing being claimed.

        Both are checked now: the index mode, which is what an installing user receives, and the
        working tree, because a shim that is not executable HERE cannot be run by the tests below.
        """
        done = subprocess.run(["git", "ls-files", "-s", "--", str(SHIM.relative_to(REPO))],
                              cwd=REPO, capture_output=True, text=True, timeout=60)
        _ck(done.returncode == 0 and done.stdout.strip(),
            f"git does not track {SHIM}; its recorded mode cannot be read, and absence is not "
            f"a pass")
        mode = done.stdout.split()[0]
        _ck(mode == "100755",
            f"git records mode {mode} for hooks/dispatch.sh; it must be 100755, because that is "
            f"the bit an installing user receives. A local chmod does not change it.")
        _ck(os.access(SHIM, os.X_OK),
            "hooks/dispatch.sh is not executable in this checkout, so the shim tests below "
            "cannot run it")

    def test_hook_uses_exec_form_for_plugin_path(self):
        config = json.loads(HOOKS.read_text())
        handler = config["hooks"]["PreToolUse"][0]["hooks"][0]
        _ck(handler["command"] == "${CLAUDE_PLUGIN_ROOT}/hooks/dispatch.sh")
        _ck(handler["args"] == [])

    def test_decoy_package_in_cwd_cannot_shadow_the_plugin(self):
        (self.tmp_path / "ward").mkdir()
        (self.tmp_path / "ward" / "__init__.py").write_text("")
        proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={
            "CLAUDE_PLUGIN_ROOT": str(PLUGIN),
            "PATH": f"{self.bare_python_dir}{os.pathsep}{os.environ['PATH']}",
        })
        _ck(proc.returncode == 0, proc.stderr)
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        _ck(out["permissionDecision"] == "deny")
        _ck("verify=False" in out["permissionDecisionReason"])
        _ck("ward.cert_verify_disabled" in out["permissionDecisionReason"])

    def test_unusable_plugin_root_fails_closed(self):
        proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={})  # PLUGIN_ROOT absent
        _ck(proc.returncode == 0, proc.stderr)
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        _ck(out["permissionDecision"] == "deny")
        _ck("failing closed" in out["permissionDecisionReason"])

    def test_empty_plugin_root_fails_closed(self):
        proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={"CLAUDE_PLUGIN_ROOT": ""})
        _ck(proc.returncode == 0, proc.stderr)
        _ck(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny")

    def test_existing_non_plugin_root_fails_closed(self):
        proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={
            "CLAUDE_PLUGIN_ROOT": str(self.tmp_path),
            "PATH": f"{self.bare_python_dir}{os.pathsep}{os.environ['PATH']}",
        })
        _ck(proc.returncode == 0, proc.stderr)
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        _ck(out["permissionDecision"] == "deny")
        _ck("failing closed" in out["permissionDecisionReason"])

    def test_malformed_hook_input_fails_closed(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("CLAUDE_PLUGIN_ROOT", "PYTHONPATH")}
        env["CLAUDE_PLUGIN_ROOT"] = str(PLUGIN)
        env["WARD_STATE_DIR"] = str(self.tmp_path / "ward-test-state")
        proc = subprocess.run([str(SHIM)], input="{", text=True, capture_output=True,
                              cwd=self.tmp_path, env=env, timeout=30)
        _ck(proc.returncode == 0, proc.stderr)
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        _ck(out["permissionDecision"] == "deny")
        _ck("malformed" in out["permissionDecisionReason"])

    def test_missing_python_fails_closed(self):
        tools = self.tmp_path / "no-python"
        tools.mkdir()
        (tools / "bash").symlink_to("/bin/bash")
        proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={
            "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "PATH": str(tools),
        })
        _ck(proc.returncode == 0, proc.stderr)
        _ck(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny")

    def test_dispatcher_nonzero_exit_fails_closed(self):
        tools = self.tmp_path / "failed-python"
        tools.mkdir()
        (tools / "bash").symlink_to("/bin/bash")
        fake_python = tools / "python3"
        fake_python.write_text("#!/bin/sh\nexit 1\n")
        fake_python.chmod(0o755)
        proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={
            "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "PATH": str(tools),
        })
        _ck(proc.returncode == 0, proc.stderr)
        _ck(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny")

    def test_ward_python_names_the_interpreter_when_python3_is_not_on_path(self):
        """The override exists for a host where the interpreter is not called `python3`.

        Without it, such a host gets `command -v python3` failing and Ward denying every single
        tool call -- the right direction for a security gate and a useless machine, with no fix
        short of editing a shipped file. Ported by shape from `Causality:hooks/dispatch.sh`, which
        carries `${CAUSALITY_PYTHON:-python3}`; the failure direction is NOT ported, because that
        shim fails open by design and this one must not.
        """
        tools = self.tmp_path / "renamed-python"
        tools.mkdir()
        (tools / "bash").symlink_to("/bin/bash")
        interpreter = self.bare_python_dir / "python3"
        proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={
            "CLAUDE_PLUGIN_ROOT": str(PLUGIN), "PATH": str(tools),
            "WARD_PYTHON": str(interpreter),
        })
        _ck(proc.returncode == 0, proc.stderr)
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        # The real check fired, so the shim ran the real dispatcher through the named interpreter
        # -- not a startup denial, which would look identical at the `permissionDecision` level.
        _ck(out["permissionDecision"] == "deny", proc.stdout)
        _ck("shim could not start" not in out["permissionDecisionReason"], proc.stdout)

    def test_ward_python_naming_a_broken_interpreter_still_fails_closed(self):
        """The override may not become a way to turn Ward off by pointing it at nothing."""
        tools = self.tmp_path / "broken-override"
        tools.mkdir()
        (tools / "bash").symlink_to("/bin/bash")
        for label, target in (("nonexistent", str(self.tmp_path / "no-such-python")),
                              ("exits nonzero", "/bin/false")):
            proc = _run_shim(FLAGGED, cwd=self.tmp_path, env_overrides={
                "CLAUDE_PLUGIN_ROOT": str(PLUGIN),
                "PATH": f"{self.bare_python_dir}{os.pathsep}{str(tools)}",
                "WARD_PYTHON": target,
            })
            _ck(proc.returncode == 0, f"{label}: {proc.stderr}")
            out = json.loads(proc.stdout)["hookSpecificOutput"]
            _ck(out["permissionDecision"] == "deny", f"{label}: {proc.stdout}")
            _ck("shim could not start" in out["permissionDecisionReason"],
                f"{label}: {proc.stdout}")

    def test_allow_payload_passes_through_byte_for_byte(self):
        event = {"hook_event_name": "PreToolUse", "tool_name": "Read",
                 "tool_input": {"file_path": "/workspace/repo/a.txt"}, "cwd": "/workspace/repo"}
        proc = _run_shim(event, cwd=self.tmp_path, env_overrides={
            "CLAUDE_PLUGIN_ROOT": str(PLUGIN),
            "PATH": f"{self.bare_python_dir}{os.pathsep}{os.environ['PATH']}",
        })
        _ck(proc.returncode == 0, proc.stderr)
        _ck(proc.stdout == "{}", proc.stdout)

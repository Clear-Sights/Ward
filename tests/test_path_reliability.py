"""Reliability measurement for the path-policy check/use boundary.

Unlike the predicate unit tests, this test performs the later filesystem operation.  It
cooperatively changes a symlink after Ward returns, making the separate-process boundary
deterministic enough to measure rather than depending on scheduler luck.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ward.checks import evaluate


TRIALS = 1_000


def _write_event(file_path: Path, cwd: Path) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(file_path), "content": "measured\n"},
        "cwd": str(cwd),
    }


class PathReliability(unittest.TestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory(prefix="ward-path-reliability-")
        self.addCleanup(scratch.cleanup)
        self.tmp_path = Path(scratch.name)

    def test_allowed_path_can_resolve_outside_after_symlink_swap(self):
        """Measure Ward-allow/later-write disagreement across the check/use boundary."""
        tmp_path = self.tmp_path
        cwd = tmp_path / "workspace"
        safe = cwd / "safe"
        outside = tmp_path / "outside"
        safe.mkdir(parents=True)
        outside.mkdir()
        pivot = cwd / "pivot"

        try:
            pivot.symlink_to(safe, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"this reliability measurement requires directory symlinks: {exc}")
        pivot.unlink()

        disagreements = 0
        for trial in range(TRIALS):
            name = f"trial-{trial}.txt"
            pivot.symlink_to(safe, target_is_directory=True)
            requested = pivot / name

            verdict = evaluate(_write_event(requested, cwd))
            assert verdict is None, f"trial {trial}: Ward unexpectedly denied the in-cwd path"

            # The writer is a separate actor: change live resolution only after Ward returns.
            pivot.unlink()
            pivot.symlink_to(outside, target_is_directory=True)
            requested.write_text("measured\n", encoding="utf-8")

            outside_result = outside / name
            if outside_result.read_text(encoding="utf-8") == "measured\n":
                disagreements += 1
            assert not (safe / name).exists()

            outside_result.unlink()
            pivot.unlink()

        print(
            "Ward path reliability: "
            f"{disagreements}/{TRIALS} allowed validations wrote outside cwd "
            f"({disagreements / TRIALS:.1%} disagreement)"
        )
        assert disagreements == TRIALS

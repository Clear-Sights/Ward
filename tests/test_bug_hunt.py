"""Regression tests for bugs found in the 2026-11-06 cleanup. Each fails on the code before its fix."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

from tools import citations, measure, register_map
from ward import checks, journal

REPO = pathlib.Path(__file__).resolve().parent.parent


def _load_replay():
    spec = importlib.util.spec_from_file_location("replay_under_test", REPO / "eval" / "replay.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NotebookProse(unittest.TestCase):
    def test_markdown_only_notebook_is_not_scanned_as_raw_json(self) -> None:
        doc = {"cells": [{"cell_type": "markdown", "metadata": {}, "source": ["verify=False is bad"]}],
               "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
        out = checks.scan_introduced_text({"file_path": "n.ipynb", "content": json.dumps(doc)})
        self.assertEqual((), out)

    def test_unparseable_notebook_is_still_scanned_as_text(self) -> None:
        out = checks.scan_introduced_text({"file_path": "n.ipynb", "content": "verify=False"})
        self.assertEqual(("verify=False",), out)


class ReplayEmptyReason(unittest.TestCase):
    def test_deny_with_empty_reason_is_a_fire(self) -> None:
        replay = _load_replay()
        deny = {"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": ""}}
        result = {"decision": deny, "exit": 0, "parsed": True, "stderr": ""}
        self.assertIsNotNone(replay.fired(result))
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "s.jsonl"
            path.write_text(json.dumps({"description": "d", "expect": "none"}) + "\n{}\n")
            with mock.patch.object(replay, "dispatch", return_value=result), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(replay.replay(path))


class RegisterMapStrict(unittest.TestCase):
    def _run(self, rows: str) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            tsv = pathlib.Path(tmp) / "map.tsv"
            tsv.write_text("entry\tverdict\trunner\tnote\n" + rows, encoding="utf-8")
            entries = [ln.split()[0] for ln in register_map.REGISTER.read_text(encoding="utf-8").splitlines()
                       if register_map.ENTRY_RX.match(ln)]
            lines = "".join(f"{e}\tOUT-OF-SUBJECT\t-\tnote\n" for e in entries[1:])
            tsv.write_text("entry\tverdict\trunner\tnote\n" + rows + lines, encoding="utf-8")
            self.first = entries[0]
            with mock.patch.object(register_map, "MAP", tsv), contextlib.redirect_stdout(io.StringIO()):
                return register_map.main()

    def _first_entry(self) -> str:
        return next(ln.split()[0] for ln in register_map.REGISTER.read_text(encoding="utf-8").splitlines()
                    if register_map.ENTRY_RX.match(ln))

    def test_runner_verdict_without_a_runner_is_not_evaluable(self) -> None:
        self.assertEqual(2, self._run(f"{self._first_entry()}\tRUNNER\t-\tnote\n"))

    def test_malformed_row_is_reported_not_a_traceback(self) -> None:
        self.assertEqual(2, self._run(f"{self._first_entry()}\tOUT-OF-SUBJECT\t-\n"))


class JournalSurrogateSession(unittest.TestCase):
    def test_lone_surrogate_session_id_gets_a_marker(self) -> None:
        self.assertTrue(journal._marker_name("\ud800"))


class MeasureOrder(unittest.TestCase):
    def test_scaffold_rows_in_reverse_order_still_count(self) -> None:
        rows = [(name, "", "") for name in reversed(measure.AST_SCAFFOLD_ROWS)]
        with mock.patch.object(measure, "checks", return_value=rows):
            self.assertEqual(len(measure.AST_SCAFFOLD_ROWS), measure.contiguous_count())


class CitationGrammar(unittest.TestCase):
    def _refs(self, text: str, *files: str) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "a.md").write_text(text, encoding="utf-8")
            for name in files:
                (root / name).write_text("x", encoding="utf-8")
            return [r.target for r in citations.relative_references(root) if r.source.name == "a.md"]

    def test_angle_bracketed_destination_with_a_space(self) -> None:
        self.assertEqual(["my notes.md"], self._refs("[x](<my notes.md>)", "my notes.md"))

    def test_destination_with_balanced_parentheses(self) -> None:
        self.assertEqual(["notes(v2).md"], self._refs("[x](notes(v2).md)", "notes(v2).md"))


if __name__ == "__main__":
    unittest.main()

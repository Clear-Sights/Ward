"""One act, three containers, one verdict -- or the table is a tax on choosing the obvious tool.

WHY THIS LAW EXISTS -- measured on this checkout before the fix. Nine content rows, one payload
each, the same source text spelled three ways:

    Write to a.py       8 of 9 FIRE
    Write to a.ipynb    0 of 9 fire
    NotebookEdit        0 of 9 fire

Eight of nine rows were evaded by choosing the notebook spelling of the identical act. Two
independent gates each excluded notebooks: the seven AST checks required `tool_input["file_path"]`
to end in `.py` (a NotebookEdit has no `file_path` at all -- it has `notebook_path`), and the two
text checks required a tool in `{Write, Edit, MultiEdit}` and a suffix set with no `.ipynb`.

Meanwhile `_PATH_MUTATION_NAMES` and `_cannot_evaluate` ALREADY knew `NotebookEdit` and
`notebook_path`. Notebooks were half-wired: the path half saw them, the content half did not --
which is why the gap read as deliberate scoping in review. The module's own comment even said so:
`NotebookEdit` "has never been covered ... whether it belongs is a scope question [to] be answered
once, here". The measurement above is that answer.

THE CELLS BELOW ARE A PARITY LAW, NOT A NOTEBOOK FIRE-CASE. A fire-case asserts that today's
predicate catches today's notebook example; parity asserts the property that actually matters --
that changing the CONTAINER changes no verdict -- and it keeps holding when a row's recognizer is
later widened, because every container is asserted against the same payload. It also fails for a
NEW row that forgets notebooks, which a hand-written notebook example per row would not.

The mention/act direction is asserted too, and it is why prose cells are excluded: the first
version of this fix scanned every cell, and a markdown cell reading `verify=False is bad` fired
`self_mute_guard` immediately. A mention of a disable is not a disable. Ward had already settled
that question -- `.md` is deliberately absent from `_MUTATION_TEXT_SUFFIX_RX` -- so a prose cell is
treated as the documentation file it is.
"""
from __future__ import annotations

import json
import unittest

from ward.checks import evaluate

# One payload per content row that reads introduced source. Each is the shape that row exists to
# catch, taken from the row's own established fire-example rather than invented here.
PAYLOADS = {
    "ward.cert_verify_disabled": "import requests\nrequests.get(u, verify=False)\n",
    "ward.jwt_none_alg": 'import jwt\njwt.decode(t, k, algorithms=["none"])\n',
    "ward.jwt_signature_disabled":
        'import jwt\njwt.decode(t, k, options={"verify_signature": False})\n',
    "ward.cert_reqs_none": "import ssl, urllib3\nurllib3.PoolManager(cert_reqs=ssl.CERT_NONE)\n",
    "ward.cert_none_mode":
        "import ssl\nc = ssl.create_default_context()\nc.verify_mode = ssl.CERT_NONE\n",
    "ward.paramiko_host_key_weakened":
        "import paramiko\nc = paramiko.SSHClient()\n"
        "c.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n",
    "ward.timing_unsafe_compare":
        "def f(sig, expected_signature):\n    return sig == expected_signature\n",
    "ward.integrity_suppression_flag":
        'import os\nif os.getenv("VERIFY_CHECK_SKIP"):\n    pass\n',
}


def _notebook(cells: list[dict]) -> str:
    return json.dumps({"cells": cells, "metadata": {}, "nbformat": 4, "nbformat_minor": 5})


def _code(src: str) -> dict:
    return {"cell_type": "code", "source": src.splitlines(keepends=True)}


def _markdown(src: str) -> dict:
    return {"cell_type": "markdown", "source": src.splitlines(keepends=True)}


def _write(path: str, content: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Write",
            "tool_input": {"file_path": path, "content": content}}


def _notebook_edit(source: str, cell_type: str = "code") -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "NotebookEdit",
            "tool_input": {"notebook_path": "/workspace/repo/a.ipynb", "new_source": source,
                           "cell_type": cell_type, "edit_mode": "replace"}}


def _containers(source: str) -> dict[str, dict]:
    """The same act, spelled three ways. A fourth container belongs here, not in a new test."""
    return {
        "Write .py": _write("/workspace/repo/a.py", source),
        "Write .ipynb document": _write("/workspace/repo/a.ipynb",
                                        _notebook([_markdown("# notes\n"), _code(source)])),
        "NotebookEdit cell": _notebook_edit(source),
    }


class ChangingTheContainerChangesNoVerdict(unittest.TestCase):
    def test_the_population_is_stated(self) -> None:
        """A parity law over a silently shrinking payload set proves nothing."""
        self.assertEqual(len(PAYLOADS), 8, "payload set moved; re-measure rather than edit")

    def test_TEETH_every_row_fires_in_every_container(self) -> None:
        """The defeat itself: 8 of these 9 spellings were silent before the fix."""
        for check_id, source in PAYLOADS.items():
            for container, event in _containers(source).items():
                with self.subTest(check=check_id, container=container):
                    verdict = evaluate(event)
                    self.assertIsNotNone(
                        verdict, f"{check_id} is silent via {container} -- the guard is evaded by "
                                 f"choosing that container")

    def test_PARITY_the_containers_agree_row_by_row(self) -> None:
        """Stated as agreement, so it still means something if a recognizer is later widened or
        narrowed: the containers must move TOGETHER, and either direction of disagreement fails."""
        for check_id, source in PAYLOADS.items():
            verdicts = {name: evaluate(event) is not None
                        for name, event in _containers(source).items()}
            with self.subTest(check=check_id):
                self.assertEqual(len(set(verdicts.values())), 1,
                                 f"{check_id}: containers disagree: {verdicts}")

    def test_NON_VACUITY_clean_source_stays_silent_in_every_container(self) -> None:
        """Denying every notebook would satisfy the cells above and destroy the tool."""
        for container, event in _containers("import requests\nrequests.get(u, verify=True)\n").items():
            with self.subTest(container=container):
                self.assertIsNone(evaluate(event))

    def test_a_MENTION_in_a_prose_cell_is_not_an_act(self) -> None:
        """The false positive the first draft of the fix produced, kept as a cell so it cannot
        return: a markdown cell is a documentation file that happens to live in a notebook."""
        self.assertIsNone(evaluate(_notebook_edit("verify=False is bad, never do it\n", "markdown")))
        self.assertIsNone(evaluate(_write(
            "/workspace/repo/a.ipynb", _notebook([_markdown("verify=False is bad\n")]))))

    def test_a_document_that_is_not_a_notebook_is_not_invented_into_one(self) -> None:
        """Declining to parse must not manufacture a fragment to judge."""
        for content in ('{"not": "a notebook"}', "this is not json at all", "{}", "[]"):
            with self.subTest(content=content[:20]):
                self.assertIsNone(evaluate(_write("/workspace/repo/a.ipynb", content)))

    def test_the_check_can_fail(self) -> None:
        """The fault is the ORIGINAL exclusion restored -- the notebook tool dropped from the
        text-scanning set and the AST gate back on `file_path` ending in `.py` -- driven through
        the production `evaluate`, and restored in `finally` whichever way the assertions go."""
        from ward import checks
        original_reader = checks.scan_introduced_python
        original_names = checks._TEXT_MUTATION_NAMES

        def py_only(tool_input: dict) -> tuple[str, ...]:
            fp = tool_input.get("file_path", "")
            if not isinstance(fp, str) or not checks._PY_FILE_RX.search(fp):
                return ()
            return checks.scan_target_contents(tool_input)

        checks.scan_introduced_python = py_only
        checks._TEXT_MUTATION_NAMES = frozenset({"Write", "Edit", "MultiEdit"})
        try:
            source = PAYLOADS["ward.cert_verify_disabled"]
            containers = _containers(source)
            self.assertIsNone(evaluate(containers["NotebookEdit cell"]),
                              "the plant did not plant: NotebookEdit still fired")
            self.assertIsNone(evaluate(containers["Write .ipynb document"]),
                              "the plant did not plant: the notebook document still fired")
            self.assertIsNotNone(evaluate(containers["Write .py"]),
                                 "the plant broke the .py path too, so it does not isolate the gap")
        finally:
            checks.scan_introduced_python = original_reader
            checks._TEXT_MUTATION_NAMES = original_names
        self.assertIsNotNone(evaluate(_notebook_edit(PAYLOADS["ward.cert_verify_disabled"])),
                             "restore failed")


if __name__ == "__main__":
    unittest.main()

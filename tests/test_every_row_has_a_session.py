"""Every row of the table is driven end to end by a session that names it.

The unit tests in `test_checks.py` already fire all eleven rows, and they fire them by calling
`evaluate` in process. That answers whether the predicate matches; it does not answer whether the
row is still REACHABLE through the shim, the dispatcher and the ordered table -- and this table is
first-match-wins, so an earlier row shadowing a later one is invisible to every in-process test.

`eval/replay.py` drives the real entrypoint, and until its sessions declared a rule it could only
report that SOMETHING denied in time. A session named for one row passed on a denial from any
other, so a corpus file was evidence that the table fires, never evidence about the row in its
filename. With `rule` declared and checked there, a session is evidence about exactly one row --
and this law is what makes the set of them a denominator rather than a sample.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path

from ward.checks import CHECKS

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "eval" / "corpus"

# A denial Ward emits that is deliberately NOT a row in CHECKS. `_cannot_evaluate` is the
# fail-closed preflight, kept outside the table so the substantive predicates remain the
# advertised eleven -- but the host still receives it as a denial, and it is the direction
# that most needs end-to-end evidence: it is what Ward does when it CANNOT see the change
# it is being asked to judge. Named here rather than admitted silently, so a future denial
# outside CHECKS is a decision someone makes out loud instead of a session that quietly
# stops meaning anything.
PREFLIGHT_DENIALS = {"ward.cannot_evaluate"}


def declared_rules() -> dict[str, str]:
    """{rule id: session filename} over every corpus session that declares one."""
    out = {}
    for session in sorted(CORPUS.glob("*.jsonl")):
        header = json.loads(session.read_text().splitlines()[0])
        if header.get("rule"):
            out[header["rule"]] = session.name
    return out


class EveryRowIsDrivenEndToEnd(unittest.TestCase):
    def test_every_table_row_has_a_session_that_names_it(self) -> None:
        declared = declared_rules()
        missing = sorted(row_id for row_id, _, _ in CHECKS if row_id not in declared)
        self.assertFalse(
            missing,
            f"these rows are never driven through the real entrypoint: {missing}. Each is fired "
            f"in process by test_checks.py, which cannot see whether an earlier row in this "
            f"ordered table shadows it. Add a session to eval/corpus declaring the row.")

    def test_every_session_declares_a_row_that_exists(self) -> None:
        known = {row_id for row_id, _, _ in CHECKS} | PREFLIGHT_DENIALS
        for session in sorted(CORPUS.glob("*.jsonl")):
            header = json.loads(session.read_text().splitlines()[0])
            rule = header.get("rule")
            if rule is None:
                self.assertEqual(
                    header.get("expect"), "none",
                    f"{session.name} names no rule and is not a control session; a session that "
                    f"names no rule is evidence about nothing")
                continue
            self.assertIn(rule, known,
                          f"{session.name} declares {rule}, which is not a row in CHECKS")

    def test_every_preflight_denial_is_driven_end_to_end(self) -> None:
        """The fail-closed path needs a session for the same reason every row does.

        `test_checks.py` fires the preflight in process, which cannot see whether the real
        dispatcher reaches it at all, nor whether an earlier row denies first and hides it.
        A denial nothing has been observed producing through the real entry point is a
        claim about behaviour, not evidence of it.
        """
        declared = set(declared_rules())
        missing = sorted(PREFLIGHT_DENIALS - declared)
        self.assertFalse(
            missing,
            f"these denials are never driven through the real entrypoint: {missing}. Add a "
            f"session to eval/corpus declaring one.")

    def test_the_corpus_is_actually_driven_and_every_session_passes(self) -> None:
        """The two laws above are about DECLARATIONS. On their own they do not drive anything.

        This module's own docstring says every row is "driven end to end", and the driving is
        `eval/replay.py`: it dispatches each session's events through the real entrypoint and
        requires the FIRST fire to name the rule the session's header declares -- which is what
        turns a corpus file into evidence about one row rather than evidence that the table fires
        at all. But nothing here made that happen. The declarations could be perfect while the
        replay was broken, removed from CI, or passing zero sessions, and these tests would stay
        green while the docstring above went on claiming end-to-end coverage.

        So the replay is run here, from this file, and its own denominator is read: exit code 0,
        `failed=0`, and `sessions` equal to the number of corpus files, so a replay that silently
        stopped collecting most of them cannot satisfy this either. Absence is not a pass."""
        corpus = sorted(CORPUS.glob("*.jsonl"))
        self.assertTrue(corpus, "no corpus sessions, so nothing below is being driven")
        done = subprocess.run(
            [sys.executable, "eval/replay.py"], cwd=REPO, capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": "plugin"}, timeout=600)
        self.assertEqual(0, done.returncode,
                         f"eval/replay.py exited {done.returncode}; the corpus is not being "
                         f"driven clean:\n{done.stdout[-2000:]}\n{done.stderr[-2000:]}")
        found = re.search(r"REPLAY sessions=(\d+) passed=(\d+) failed=(\d+)", done.stdout)
        self.assertIsNotNone(
            found, f"eval/replay.py printed no denominator, so its exit code stands on "
                   f"nothing:\n{done.stdout[-2000:]}")
        sessions, passed, failed = (int(g) for g in found.groups())
        self.assertEqual(0, failed, done.stdout[-2000:])
        self.assertEqual(len(corpus), sessions,
                         f"eval/corpus holds {len(corpus)} sessions and the replay drove "
                         f"{sessions}; a session that is never replayed is evidence about nothing")
        self.assertEqual(sessions, passed, done.stdout[-2000:])

    def test_the_replay_isolates_its_state_instead_of_writing_the_real_journal(self) -> None:
        """The corpus replay must not append to the journal a developer is actually using.

        eval/replay.py creates a temporary state directory per session and passed it under
        `WARD_UNUSED_STATE`, over a comment reading "ward is stateless; the variable is set and
        ignored". That stopped being true when journal.py began recording decisions: Ward reads
        WARD_STATE_DIR, so every replayed session was appending to `~/.claude/ward_state` while
        the temporary directory sat unused beside it. The isolation was decorative.

        The witness is the ambient value: point WARD_STATE_DIR at a directory of our own, run the
        whole replay, and require that directory to be untouched. If replay ever stops overriding
        it per session, the journal lands here and this goes red."""
        with tempfile.TemporaryDirectory(prefix="ward-ambient-state-") as ambient:
            done = subprocess.run(
                [sys.executable, "eval/replay.py"], cwd=REPO, capture_output=True, text=True,
                env={**os.environ, "PYTHONPATH": "plugin", "WARD_STATE_DIR": ambient},
                timeout=600)
            self.assertEqual(0, done.returncode, done.stdout[-2000:])
            leaked = sorted(p.name for p in Path(ambient).iterdir())
            self.assertEqual(
                [], leaked,
                f"the replay wrote {leaked} into the ambient WARD_STATE_DIR; a corpus run must "
                f"not append to the journal a developer is using")

    def test_the_check_can_fail(self) -> None:
        """Planted: a row absent from the corpus must be reported by name."""
        declared = declared_rules()
        declared.pop("ward.self_mute_guard", None)
        missing = sorted(row_id for row_id, _, _ in CHECKS if row_id not in declared)
        self.assertEqual(missing, ["ward.self_mute_guard"])


if __name__ == "__main__":
    unittest.main()

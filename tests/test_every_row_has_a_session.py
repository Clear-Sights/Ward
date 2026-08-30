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

    def test_the_check_can_fail(self) -> None:
        """Planted: a row absent from the corpus must be reported by name."""
        declared = declared_rules()
        declared.pop("ward.self_mute_guard", None)
        missing = sorted(row_id for row_id, _, _ in CHECKS if row_id not in declared)
        self.assertEqual(missing, ["ward.self_mute_guard"])


if __name__ == "__main__":
    unittest.main()

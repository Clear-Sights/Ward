"""A Write and an Edit that remove the same verifier must reach the same verdict.

WHY THIS LAW EXISTS -- the defeat it was written against, measured on this checkout before the
fix. Same file, same verifier, same removal, two spellings of one act:

    Edit  (old_string -> new_string dropping `verify_signature`)   DENIED
    Write (whole-file content dropping `verify_signature`)         ALLOWED

`ward.self_mute_guard` compares the symbols a mutation REMOVES against the ones it introduces, and
`_removed_contents` sourced the removed side from the payload alone -- `old_string` for Edit, each
`edits[].old_string` for MultiEdit. A Write ships neither, so its removed side was empty by
construction and the symbol half of the predicate could never run for it. That is not a gap in
coverage, it is a DEFEAT: the guard held only while the agent chose the guarded tool.

So the cells below are written as a PARITY law rather than as a Write fire-case. A fire-case
asserts that today's predicate catches today's example; parity asserts the property that actually
matters -- that choosing the other tool buys nothing -- and it keeps holding if either side's
recognizer is later widened, because both sides are asserted against the same removal.

The bounded-read direction is asserted too, because the fix reads the target from disk and a read
must never invent a removal: a Write that CREATES a file removes nothing, and an unreadable or
oversized target yields no removed text rather than a guess.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ward.checks import evaluate

WITH_VERIFIER = "def verify_signature(x):\n    return x.ok\n\ndef main():\n    pass\n"
WITHOUT = "def main():\n    pass\n"


def _pre(tool_name: str, tool_input: dict) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": tool_name, "tool_input": tool_input}


class WriteAndEditReachTheSameVerdict(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.target = self.dir / "v.py"
        self.target.write_text(WITH_VERIFIER, encoding="utf-8")

    def _verdict(self, event: dict):
        return evaluate(event)

    def test_TEETH_a_whole_file_write_cannot_launder_a_verifier_removal(self) -> None:
        """The defeat itself: this was ALLOWED, and the Edit spelling of it was DENIED."""
        verdict = self._verdict(_pre("Write", {"file_path": str(self.target), "content": WITHOUT}))
        self.assertIsNotNone(verdict, "a Write dropping `verify_signature` was allowed")
        self.assertEqual(verdict[0], "ward.self_mute_guard")

    def test_PARITY_the_edit_spelling_reaches_the_same_verdict(self) -> None:
        """The control, and the reason the cell above is a parity claim rather than a fire-case.

        If this one ever goes silent the law still means something: the two sides must AGREE, and
        a disagreement in either direction is the finding."""
        write = self._verdict(_pre("Write", {"file_path": str(self.target), "content": WITHOUT}))
        edit = self._verdict(_pre("Edit", {"file_path": str(self.target),
                                           "old_string": WITH_VERIFIER, "new_string": WITHOUT}))
        self.assertEqual(write is None, edit is None,
                         f"Write and Edit disagree on the same removal: {write!r} vs {edit!r}")

    def test_NON_VACUITY_a_write_that_keeps_the_verifier_is_allowed(self) -> None:
        """Denying every Write would satisfy the cell above and destroy the tool."""
        self.assertIsNone(
            self._verdict(_pre("Write", {"file_path": str(self.target), "content": WITH_VERIFIER})))

    def test_a_write_that_CREATES_a_file_removes_nothing(self) -> None:
        """The read must not invent a removal out of an absent target."""
        self.assertIsNone(
            self._verdict(_pre("Write", {"file_path": str(self.dir / "new.py"),
                                         "content": WITHOUT})))

    def test_an_oversized_target_yields_no_removed_text_rather_than_a_guess(self) -> None:
        """The bound is on the READ, so it must not become a way to be wrong -- it declines to
        claim, and declining is silent, never a deny."""
        from ward import checks
        big = self.dir / "big.py"
        big.write_text(WITH_VERIFIER + "# pad\n" * 200_000, encoding="utf-8")
        self.assertGreater(big.stat().st_size, checks._WRITE_PRIOR_READ_MAX)
        self.assertIsNone(
            self._verdict(_pre("Write", {"file_path": str(big), "content": WITHOUT})))

    def test_the_check_can_fail(self) -> None:
        """The fault is the ORIGINAL defect restored -- `_removed_contents` blind to a Write --
        not a special case wired to this file's own inputs. Driven through the production
        `evaluate`, and restored in `finally` whichever way the assertions go."""
        from ward import checks
        original = checks._removed_contents

        def payload_only(tool_input: dict) -> tuple[str, ...]:
            old = tool_input.get("old_string")
            if isinstance(old, str) and old:
                return (old,)
            edits = tool_input.get("edits")
            if isinstance(edits, list):
                return tuple(e.get("old_string", "") for e in edits
                             if isinstance(e, dict) and isinstance(e.get("old_string"), str))
            return ()

        checks._removed_contents = payload_only
        try:
            self.assertIsNone(
                self._verdict(_pre("Write", {"file_path": str(self.target), "content": WITHOUT})),
                "the plant did not plant: the Write was still denied with the defect restored")
            self.assertIsNotNone(
                self._verdict(_pre("Edit", {"file_path": str(self.target),
                                            "old_string": WITH_VERIFIER, "new_string": WITHOUT})),
                "the plant broke the Edit side too, so it does not isolate the defect")
        finally:
            checks._removed_contents = original
        self.assertIsNotNone(
            self._verdict(_pre("Write", {"file_path": str(self.target), "content": WITHOUT})),
            "restore failed")


if __name__ == "__main__":
    unittest.main()

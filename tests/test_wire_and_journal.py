"""The byte boundary, and the record that Ward ran.

TWO DEFECTS, ONE INPUT.

1. A host byte that is not valid UTF-8 arrived as a LONE SURROGATE (`sys.stdin.read()` under the
   C locale gets the `surrogateescape` handler), `ast.parse` refused it, and `_cannot_evaluate`
   turned that into a HARD DENY reading "introduced Python fragment cannot be parsed
   independently" -- about a fragment that parses fine. Fail-closed was the right direction on a
   false fact, which makes the deny unactionable: the agent rewrites code that was never the
   problem, the byte survives every rewrite, and the loop does not heal.

2. Ward kept no record at all. "Was Ward running, and did it stop anything?" had no file to consult
   anywhere, so the answer was not "no" -- it was unanswerable, which cannot be distinguished from
   "never installed".

STDLIB `unittest` ONLY, DELIBERATELY. Ward's CI installs no test runner -- it is
`python -m pip install -e .` followed by `python -m unittest discover -s tests`. A pytest-style
module here is not a failing test, it is a COLLECTION ERROR that takes the whole discovery run
down with it, on every matrix leg, whatever the other tests would have said. Every pre-existing
file in this directory is `unittest.TestCase` for that reason; validate changes here with
`python -m unittest discover -s tests`, not with a locally installed pytest, which masks it.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

BENIGN_PY_WITH_BAD_BYTE = (
    b'{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"w-benign",'
    b'"cwd":"/tmp","tool_input":{"file_path":"/tmp/ok.py","content":"# caf\x9d\\nprint(1)\\n"}}'
)
VIOLATION_PY_WITH_BAD_BYTE = (
    b'{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"w-bad",'
    b'"cwd":"/tmp","tool_input":{"file_path":"/tmp/bad.py",'
    b'"content":"import ssl # caf\x9d\\nctx = ssl._create_unverified_context()\\n"}}'
)


def _run(raw: bytes, state_dir) -> tuple:
    env = os.environ.copy()
    env["WARD_STATE_DIR"] = str(state_dir)
    proc = subprocess.run([sys.executable, "-m", "ward.dispatch"], input=raw,
                          capture_output=True, env=env, cwd=str(REPO_ROOT))
    return proc.returncode, json.loads(proc.stdout.decode() or "{}")


def _rows(state_dir) -> list:
    f = Path(state_dir) / "decisions.jsonl"
    if not f.exists():
        return []
    return [json.loads(ln) for ln in f.read_text().splitlines() if ln.strip()]


def _reason(body: dict) -> str:
    return body.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")


class StateCase(unittest.TestCase):
    """A private WARD_STATE_DIR per test, so one test's journal cannot be read as another's."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)


# --- the false deny --------------------------------------------------------------------------

class TestTheFalseDeny(StateCase):
    def test_undecodable_byte_no_longer_denies_a_benign_file(self):
        code, body = _run(BENIGN_PY_WITH_BAD_BYTE, self.state)
        self.assertEqual(code, 0)
        self.assertEqual(body, {},
                         "a valid Python file must not be denied over one stray byte: %r" % (body,))

    def test_the_old_reason_is_specifically_gone(self):
        """Pin the false reason itself, not merely 'did not deny'. A future change that reintroduces
        the deny under any wording should fail here with the wording named."""
        _code, body = _run(BENIGN_PY_WITH_BAD_BYTE, self.state)
        self.assertNotIn("cannot be parsed independently", _reason(body))

    def test_real_violation_with_a_bad_byte_still_denies(self):
        """The repair must not blunt the gate. Same stray byte, real weakened-TLS mutation."""
        code, body = _run(VIOLATION_PY_WITH_BAD_BYTE, self.state)
        self.assertEqual(code, 0)
        self.assertIn("ward.cert_verify_disabled", _reason(body))

    def test_genuinely_unparseable_input_still_fails_closed(self):
        """Ward's fail direction is unchanged: a fragment that really cannot be parsed still denies."""
        raw = (b'{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"w-syn",'
               b'"cwd":"/tmp","tool_input":{"file_path":"/tmp/x.py","content":"def ((("}}')
        _code, body = _run(raw, self.state)
        self.assertIn("ward.cannot_evaluate", _reason(body))

    def test_malformed_envelope_still_fails_closed(self):
        _code, body = _run(b"not json{{{", self.state)
        self.assertIn("failing closed", _reason(body))

    def test_unpaired_surrogate_escape_is_closed_too(self):
        """The other door: valid UTF-8 whose JSON text carries an unpaired \\uD8xx escape."""
        raw = (b'{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"w-esc",'
               b'"cwd":"/tmp","tool_input":{"file_path":"/tmp/ok.py",'
               b'"content":"# a\\ud89d\\nprint(1)\\n"}}')
        code, body = _run(raw, self.state)
        self.assertEqual(code, 0)
        self.assertEqual(body, {})


# --- the record ------------------------------------------------------------------------------

class TestTheRecord(StateCase):
    def test_a_session_row_proves_ward_ran(self):
        """The liveness proof. Without it an empty log cannot be told apart from a plugin that was
        never installed -- and both look exactly like a clean session."""
        _run(BENIGN_PY_WITH_BAD_BYTE, self.state)
        sessions = [r for r in _rows(self.state) if r["kind"] == "session"]
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["session_id"], "w-benign")
        self.assertEqual(sessions[0]["checks"], 11,
                         "a session row saying 0 checks is a Ward that inspected nothing")

    def test_session_row_is_written_once_not_once_per_call(self):
        for _ in range(3):
            _run(BENIGN_PY_WITH_BAD_BYTE, self.state)
        self.assertEqual(len([r for r in _rows(self.state) if r["kind"] == "session"]), 1)

    def test_every_row_names_plugin_session_and_tool(self):
        """The attribution that makes a row joinable. Three plugins register PreToolUse `*` and the
        host does not say which one spoke."""
        _run(VIOLATION_PY_WITH_BAD_BYTE, self.state)
        rows = _rows(self.state)
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["plugin"], "ward")
            self.assertEqual(row["session_id"], "w-bad")
            self.assertEqual(row["tool_name"], "Write")
            self.assertEqual(row["hook_event"], "PreToolUse")

    def test_deny_row_names_the_check(self):
        _run(VIOLATION_PY_WITH_BAD_BYTE, self.state)
        denies = [r for r in _rows(self.state) if r["kind"] == "deny"]
        self.assertEqual(len(denies), 1)
        self.assertEqual(denies[0]["check_id"], "ward.cert_verify_disabled")

    def test_repair_is_recorded_but_is_not_a_fault(self):
        """A repaired event WAS evaluated. Filing it as a fault would inflate the count of
        unevaluated calls, which is the one number this log exists to keep honest."""
        _run(BENIGN_PY_WITH_BAD_BYTE, self.state)
        rows = _rows(self.state)
        self.assertEqual([r for r in rows if r["kind"] == "repair"][0]["repaired"], 1)
        self.assertEqual([r for r in rows if r["kind"] == "fault"], [])

    def test_fault_rows_record_which_way_ward_fell(self):
        """`failed_closed` makes the suite's fail-direction policy auditable, not merely documented."""
        _run(b"not json{{{", self.state)
        faults = [r for r in _rows(self.state) if r["kind"] == "fault"]
        self.assertEqual(len(faults), 1)
        self.assertIs(faults[0]["failed_closed"], True)

    def test_a_clean_call_writes_no_deny_row(self):
        """Fires-only, by design: a row per allowed call runs 99%+ noise and drowns the signal."""
        raw = (b'{"hook_event_name":"PreToolUse","tool_name":"Read","session_id":"w-quiet",'
               b'"cwd":"/tmp","tool_input":{"file_path":"/tmp/a.txt"}}')
        _run(raw, self.state)
        self.assertEqual({r["kind"] for r in _rows(self.state)}, {"session"})

    def test_journal_failure_never_changes_a_verdict(self):
        """Observability must never become policy. A gate that denied because its logger could not
        write would be a worse bug than the missing log."""
        from ward import journal
        from ward.dispatch import route

        original = journal._append
        journal._append = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
        self.addCleanup(setattr, journal, "_append", original)

        event = json.loads(BENIGN_PY_WITH_BAD_BYTE.decode("utf-8", "replace"))
        self.assertEqual(route(event), {})


# --- unit guarantees of the boundary ---------------------------------------------------------

class TestBoundaryUnits(unittest.TestCase):
    def test_scrub_counts_and_removes(self):
        from ward import wire
        text, n = wire.scrub_text("a\ud89db\udc9dc")
        self.assertEqual(n, 2)
        self.assertFalse(any("\ud800" <= c <= "\udfff" for c in text))

    def test_legitimate_replacement_char_is_not_counted_as_damage(self):
        from ward import wire
        _text, n = wire._decode_counting("legit � char".encode("utf-8"))
        self.assertEqual(n, 0, "a payload that genuinely contains U+FFFD is clean, not damaged")

    def test_repair_count_is_bytes_not_malformed_runs(self):
        """Found by an independent review pass. `errors="replace"` emits ONE U+FFFD per malformed
        RUN, so a truncated three-byte sequence -- two undecodable bytes -- reported 1, under a
        field named "bytes repaired". `surrogateescape` maps each bad BYTE to one surrogate, so the
        count means what the field says."""
        from ward import wire
        self.assertEqual(wire._decode_counting(b"\xe2\x82")[1], 2)
        self.assertEqual(wire._decode_counting(b"x\x9dy")[1], 1)

    def test_clean_value_is_returned_untouched(self):
        from ward import wire
        original = {"a": ["b", {"c": "d"}]}
        value, n = wire.scrub(original)
        self.assertEqual(n, 0)
        self.assertIs(value, original)


# --- regressions found by an independent high-effort review pass ------------------------------

class TestFailClosedIsTotal(StateCase):
    """Ward's promise is that it fails closed on EVERY envelope it cannot inspect.

    `main` caught only `ValueError`. That is what `json.loads` raises for the malformed text the
    arm was written for -- but a deeply nested document raises `RecursionError`, and `wire.scrub`
    walks the parsed value recursively and raises the same on the same input. Neither is a
    `ValueError`, so both crashed out of `main()` and the hook exited 1 having written NOTHING to
    stdout. A hook that emits no decision is a hook that allowed the call.

    The exception TYPE is deliberately not asserted from the nested-JSON case: how deep a document
    CPython will parse before it gives up is a property of the interpreter, not of Ward. Measured
    3.11 raising `RecursionError` at depth 2000 where 3.12 parsed the same input and reported the
    ordinary not-an-object refusal instead. Pinning the type there pins the wrong thing and goes
    red on a version bump; the injection test below pins the actual contract with no dependence on
    any of that.
    """

    def _deep_object(self):
        # An OBJECT, not an array: an array is refused by the not-a-JSON-object guard before
        # anything recursive runs, so it never exercised the path this class is about. Depth is
        # taken from the live limit so the input stays deep on an interpreter with a larger one.
        depth = sys.getrecursionlimit() * 20
        return (b'{"tool_input":' + b'{"a":' * depth + b'1' + b'}' * depth + b'}')

    def test_a_document_too_deep_to_inspect_still_denies(self):
        code, body = _run(self._deep_object(), self.state)
        self.assertEqual(code, 0, "a crash exit means the hook emitted no decision at all")
        self.assertIn("failing closed", _reason(body),
                      "an envelope Ward could not inspect must never be allowed through")

    def test_a_non_valueerror_from_the_read_still_denies_and_is_recorded(self):
        """The contract itself, injected rather than provoked: whatever `read_event` raises, Ward
        denies, exits 0, and files a fault naming the type."""
        import contextlib
        import io

        from ward import dispatch, journal, wire

        original_read, original_state = wire.read_stdin, journal.state_dir
        wire.read_stdin = lambda: (_ for _ in ()).throw(RecursionError("too deep"))
        journal.state_dir = lambda: self.state
        self.addCleanup(setattr, wire, "read_stdin", original_read)
        self.addCleanup(setattr, journal, "state_dir", original_state)

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = dispatch.main()

        self.assertEqual(code, 0)
        self.assertIn("failing closed", _reason(json.loads(out.getvalue() or "{}")))
        faults = [r for r in _rows(self.state) if r["kind"] == "fault"]
        self.assertEqual(len(faults), 1)
        self.assertIn("RecursionError", faults[0]["detail"],
                      "the fault row must name what went wrong, not merely that something did")
        self.assertIs(faults[0]["failed_closed"], True)


class TestTheSessionRowIsExactlyOnce(StateCase):
    """Three separate defects in one function, all of them costing the liveness row this journal
    exists to guarantee."""

    def test_ids_differing_only_in_punctuation_are_not_one_session(self):
        """`a/b` and `a?b` both sanitized to `a_b`, so the second session was read as already
        noted and its row was never written."""
        from ward import journal
        journal.note_session({"session_id": "a/b", "tool_name": "T"}, root=self.state)
        journal.note_session({"session_id": "a?b", "tool_name": "T"}, root=self.state)
        got = sorted(r["session_id"] for r in _rows(self.state) if r["kind"] == "session")
        self.assertEqual(got, ["a/b", "a?b"])

    def test_a_failed_append_does_not_suppress_the_row_forever(self):
        """The marker was committed BEFORE the row, so one swallowed write error silenced this
        session's liveness row for the rest of its life."""
        from ward import journal
        original = journal._append
        journal._append = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
        self.addCleanup(setattr, journal, "_append", original)
        journal.note_session({"session_id": "s1", "tool_name": "T"}, root=self.state)
        journal._append = original
        journal.note_session({"session_id": "s1", "tool_name": "T"}, root=self.state)
        self.assertEqual(len([r for r in _rows(self.state) if r["kind"] == "session"]), 1)

    def test_concurrent_processes_write_one_row_between_them(self):
        """`exists()` then write is check-then-act, and concurrent hook processes are the normal
        condition here rather than an edge case."""
        from ward import journal
        kids = []
        for _ in range(12):
            pid = os.fork()
            if pid == 0:
                try:
                    journal.note_session({"session_id": "race", "tool_name": "T"}, root=self.state)
                finally:
                    os._exit(0)
            kids.append(pid)
        for pid in kids:
            os.waitpid(pid, 0)
        self.assertEqual(len([r for r in _rows(self.state) if r["kind"] == "session"]), 1)


class TestRepairCountsMeanWhatTheyAreNamed(StateCase):
    """`repaired` counts undecodable BYTES. Summing the surrogate-ESCAPE count into it meant an
    envelope whose bytes were flawless could report bytes repaired."""

    def test_an_escape_only_envelope_reports_zero_bytes_repaired(self):
        raw = (b'{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"w-esc",'
               b'"cwd":"/tmp","tool_input":{"file_path":"/tmp/ok.py",'
               b'"content":"# a\\ud89d\\nprint(1)\\n"}}')
        _run(raw, self.state)
        repair = [r for r in _rows(self.state) if r["kind"] == "repair"][0]
        self.assertEqual(repair["repaired"], 0, "no byte on that wire was undecodable")
        self.assertEqual(repair["escaped"], 1)

    def test_a_byte_damaged_envelope_reports_zero_escapes(self):
        _run(BENIGN_PY_WITH_BAD_BYTE, self.state)
        repair = [r for r in _rows(self.state) if r["kind"] == "repair"][0]
        self.assertEqual(repair["repaired"], 1)
        self.assertEqual(repair["escaped"], 0)


if __name__ == "__main__":
    unittest.main()

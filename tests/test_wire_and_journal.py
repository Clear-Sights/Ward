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
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

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


def _run(raw: bytes, state_dir) -> tuple[int, dict]:
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


# --- the false deny --------------------------------------------------------------------------

def test_undecodable_byte_no_longer_denies_a_benign_file(tmp_path):
    code, body = _run(BENIGN_PY_WITH_BAD_BYTE, tmp_path)
    assert code == 0
    assert body == {}, f"a valid Python file must not be denied over one stray byte: {body}"


def test_the_old_reason_is_specifically_gone(tmp_path):
    """Pin the false reason itself, not merely 'did not deny'. A future change that reintroduces
    the deny under any wording should fail here with the wording named."""
    _code, body = _run(BENIGN_PY_WITH_BAD_BYTE, tmp_path)
    assert "cannot be parsed independently" not in _reason(body)


def test_real_violation_with_a_bad_byte_still_denies(tmp_path):
    """The repair must not blunt the gate. Same stray byte, real weakened-TLS mutation."""
    code, body = _run(VIOLATION_PY_WITH_BAD_BYTE, tmp_path)
    assert code == 0
    assert "ward.cert_verify_disabled" in _reason(body)


def test_genuinely_unparseable_input_still_fails_closed(tmp_path):
    """Ward's fail direction is unchanged: a fragment that really cannot be parsed still denies."""
    raw = (b'{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"w-syn",'
           b'"cwd":"/tmp","tool_input":{"file_path":"/tmp/x.py","content":"def ((("}}')
    _code, body = _run(raw, tmp_path)
    assert "ward.cannot_evaluate" in _reason(body)


def test_malformed_envelope_still_fails_closed(tmp_path):
    _code, body = _run(b"not json{{{", tmp_path)
    assert "failing closed" in _reason(body)


def test_unpaired_surrogate_escape_is_closed_too(tmp_path):
    """The other door: valid UTF-8 whose JSON text carries an unpaired \\uD8xx escape."""
    raw = (b'{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"w-esc",'
           b'"cwd":"/tmp","tool_input":{"file_path":"/tmp/ok.py","content":"# a\\ud89d\\nprint(1)\\n"}}')
    code, body = _run(raw, tmp_path)
    assert code == 0 and body == {}


# --- the record ------------------------------------------------------------------------------

def test_a_session_row_proves_ward_ran(tmp_path):
    """The liveness proof. Without it an empty log cannot be told apart from a plugin that was
    never installed -- and both look exactly like a clean session."""
    _run(BENIGN_PY_WITH_BAD_BYTE, tmp_path)
    sessions = [r for r in _rows(tmp_path) if r["kind"] == "session"]
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == "w-benign"
    assert sessions[0]["checks"] == 11, "a session row saying 0 checks is a Ward that inspected nothing"


def test_session_row_is_written_once_not_once_per_call(tmp_path):
    for _ in range(3):
        _run(BENIGN_PY_WITH_BAD_BYTE, tmp_path)
    assert len([r for r in _rows(tmp_path) if r["kind"] == "session"]) == 1


def test_every_row_names_plugin_session_and_tool(tmp_path):
    """The attribution that makes a row joinable. Three plugins register PreToolUse `*` and the
    host does not say which one spoke."""
    _run(VIOLATION_PY_WITH_BAD_BYTE, tmp_path)
    rows = _rows(tmp_path)
    assert rows
    for row in rows:
        assert row["plugin"] == "ward"
        assert row["session_id"] == "w-bad"
        assert row["tool_name"] == "Write"
        assert row["hook_event"] == "PreToolUse"


def test_deny_row_names_the_check(tmp_path):
    _run(VIOLATION_PY_WITH_BAD_BYTE, tmp_path)
    denies = [r for r in _rows(tmp_path) if r["kind"] == "deny"]
    assert len(denies) == 1 and denies[0]["check_id"] == "ward.cert_verify_disabled"


def test_repair_is_recorded_but_is_not_a_fault(tmp_path):
    """A repaired event WAS evaluated. Filing it as a fault would inflate the count of
    unevaluated calls, which is the one number this log exists to keep honest."""
    _run(BENIGN_PY_WITH_BAD_BYTE, tmp_path)
    rows = _rows(tmp_path)
    assert [r for r in rows if r["kind"] == "repair"][0]["repaired"] == 1
    assert [r for r in rows if r["kind"] == "fault"] == []


def test_fault_rows_record_which_way_ward_fell(tmp_path):
    """`failed_closed` makes the suite's fail-direction policy auditable, not merely documented."""
    _run(b"not json{{{", tmp_path)
    faults = [r for r in _rows(tmp_path) if r["kind"] == "fault"]
    assert len(faults) == 1 and faults[0]["failed_closed"] is True


def test_a_clean_call_writes_no_deny_row(tmp_path):
    """Fires-only, by design: a row per allowed call runs 99%+ noise and drowns the signal."""
    raw = (b'{"hook_event_name":"PreToolUse","tool_name":"Read","session_id":"w-quiet",'
           b'"cwd":"/tmp","tool_input":{"file_path":"/tmp/a.txt"}}')
    _run(raw, tmp_path)
    kinds = {r["kind"] for r in _rows(tmp_path)}
    assert kinds == {"session"}


def test_journal_failure_never_changes_a_verdict(tmp_path, monkeypatch):
    """Observability must never become policy. A gate that denied because its logger could not
    write would be a worse bug than the missing log."""
    from ward import journal
    monkeypatch.setattr(journal, "_append",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    from ward.dispatch import route
    event = json.loads(BENIGN_PY_WITH_BAD_BYTE.decode("utf-8", "replace"))
    assert route(event) == {}


# --- unit guarantees of the boundary ---------------------------------------------------------

def test_scrub_counts_and_removes():
    from ward import wire
    text, n = wire.scrub_text("a\ud89db\udc9dc")
    assert n == 2 and not any("\ud800" <= c <= "\udfff" for c in text)


def test_legitimate_replacement_char_is_not_counted_as_damage():
    from ward import wire
    _text, n = wire._decode_counting("legit � char".encode("utf-8"))
    assert n == 0, "a payload that genuinely contains U+FFFD is clean, not damaged"


def test_repair_count_is_bytes_not_malformed_runs():
    """Found by an independent review pass. `errors="replace"` emits ONE U+FFFD per malformed RUN,
    so a truncated three-byte sequence -- two undecodable bytes -- reported 1, under a field named
    "bytes repaired". `surrogateescape` maps each bad BYTE to one surrogate, so the count means
    what the field says."""
    from ward import wire
    assert wire._decode_counting(b"\xe2\x82")[1] == 2
    assert wire._decode_counting(b"x\x9dy")[1] == 1


def test_clean_value_is_returned_untouched():
    from ward import wire
    original = {"a": ["b", {"c": "d"}]}
    value, n = wire.scrub(original)
    assert n == 0 and value is original

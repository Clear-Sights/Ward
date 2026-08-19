"""ward.journal -- the persisted record: what Ward did, in which session, to which tool.

WHY A PLUGIN NEEDS ONE AT ALL. Ward shipped with no state and no log. That reads as a virtue --
nothing to corrupt, nothing to grow, no privacy surface -- and it is one, right up to the moment
somebody asks "was Ward running during that session, and did it stop anything?" With no file
anywhere, the answer to that is not "no". It is UNANSWERABLE, which is strictly worse, because a
gate that cannot show it ran is indistinguishable from one that was never installed, and both look
exactly like a gate that ran and found nothing.

WHAT IS RECORDED, AND WHY NOT EVERYTHING
Three row kinds, deliberately not four:

  * `session` -- ONE row the first time Ward sees a given session. This is the liveness proof, and
    it is why the log answers "did Ward run" separately from "did Ward catch anything". Without it
    an empty log is ambiguous between "clean session" and "plugin never fired"; with it, an empty
    session list means not-installed and a session row with no denies means genuinely clean.
  * `deny` -- every refusal, naming the check that produced it.
  * `fault` -- every internal error, i.e. every event Ward could not evaluate.

There is deliberately NO row per allowed call. Makoto measured that policy directly and found such
a log runs 99%+ noise; a log nobody can read is a log nobody reads, and the signal drowns.

EVERY ROW NAMES ITS PLUGIN. Ward, Gyroscope and Makoto all register PreToolUse `*`, all three can
emit a deny, and the host does not tell the user which one spoke. A row that does not name its
author is unattributable the moment more than one is installed -- which is the shipped Courthouse
configuration, not an edge case. `plugin` is that name, and the deny reason on the wire carries the
same `ward.<check_id>` prefix, so the transcript and the log can be joined after the fact.

FAILURE POSTURE: this module is OBSERVABILITY and must never change a verdict. Every entry point
swallows everything. A gate that denied because its logger could not write would be a worse bug
than the missing log.
"""
from __future__ import annotations

import json
import os
import pathlib
from datetime import datetime, timezone

PLUGIN = "ward"


def state_dir() -> pathlib.Path:
    """Ward's own store. `WARD_STATE_DIR` overrides; default `~/.claude/ward_state`.

    Own store, not a host-provided one: no `CLAUDE_PLUGIN_DATA` equivalent exists on every host
    Ward runs on, and a log that only exists on one host cannot be the record.
    """
    env = os.environ.get("WARD_STATE_DIR")
    if env:
        return pathlib.Path(env)
    if os.environ.get("CODEX_PLUGIN_ROOT") or os.environ.get("CODEX_HOME"):
        return pathlib.Path.home() / ".codex" / "ward_state"
    return pathlib.Path.home() / ".claude" / "ward_state"


def _append(row: dict, root: pathlib.Path | None = None) -> None:
    """Append one compact JSON line. POSIX guarantees atomicity for short append-mode writes
    (<= PIPE_BUF), and a row is far under, so concurrent hook processes cannot interleave."""
    root = root or state_dir()
    root.mkdir(parents=True, exist_ok=True)
    with (root / "decisions.jsonl").open("a", encoding="utf-8") as fh:
        # ensure_ascii=True keeps every byte written here in the ASCII range, so this writer cannot
        # itself become the encoding failure it exists to record.
        fh.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")


def _row(event: dict, kind: str, **extra) -> dict:
    return {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "plugin": PLUGIN,
        "kind": kind,
        "session_id": str(event.get("session_id") or ""),
        "tool_name": str(event.get("tool_name") or ""),
        "hook_event": str(event.get("hook_event_name") or ""),
        **extra,
    }


def note_session(event: dict, root: pathlib.Path | None = None) -> None:
    """Record ONCE per session that Ward was live. See the module docstring for why this exists.

    Once per session, not once per call: a marker file per session id is the whole mechanism. An
    unwritable marker degrades to re-noting -- noisy, still correct -- never to silence and never
    to raising.
    """
    try:
        session = str(event.get("session_id") or "")
        if not session:
            return
        root = root or state_dir()
        seen = root / "sessions"
        seen.mkdir(parents=True, exist_ok=True)
        key = "".join(c if c.isalnum() or c in "-_" else "_" for c in session)[:96]
        marker = seen / f"{key}"
        if marker.exists():
            return
        marker.write_text("")
        _append(_row(event, "session", checks=_check_count()), root=root)
    except Exception:
        pass


def note_deny(event: dict, check_id: str, reason: str,
              root: pathlib.Path | None = None) -> None:
    """Record a refusal, naming the check that produced it."""
    try:
        _append(_row(event, "deny", check_id=check_id, reason=reason[:400]), root=root)
    except Exception:
        pass


def note_fault(event: dict, stage: str, detail: str, *, failed_closed: bool,
               root: pathlib.Path | None = None) -> None:
    """Record an event Ward could not evaluate, and which way it fell.

    `failed_closed` is not decoration: it is the field that makes the suite's fail-direction policy
    auditable rather than merely documented. Ward's answer is always True -- see
    `ward.dispatch`'s module docstring -- and a row that ever says otherwise is a bug with its own
    evidence attached.
    """
    try:
        _append(_row(event, "fault", stage=stage, detail=detail[:400],
                     failed_closed=bool(failed_closed)), root=root)
    except Exception:
        pass


def note_repair(event: dict, repaired: int, root: pathlib.Path | None = None) -> None:
    """Record that the envelope carried bytes that had to be repaired before it could be read.

    Distinct from `fault` on purpose: the event WAS evaluated, on a repaired payload. Filing a
    repair as a fault would inflate the count of unevaluated calls, which is the one number this
    log exists to keep honest.
    """
    try:
        _append(_row(event, "repair", repaired=int(repaired)), root=root)
    except Exception:
        pass


def _check_count() -> int:
    """How many checks were loaded. Absence must not read as green: a session row saying `0` is a
    Ward that inspected nothing, and that is a different fact from a quiet session."""
    try:
        from ward.checks import CHECKS
        return len(CHECKS)
    except Exception:
        return -1

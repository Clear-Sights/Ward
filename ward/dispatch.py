"""The pivot. One PreToolUse hook entrypoint: read the event, run it through ward.checks.evaluate,
deny with the first firing check's message, or emit {} (no opinion — every one of these 11 checks
is an unconditional hard block, so there is no rewrite/advisory/defer shape to express; a future
check that needs one of those does not belong in this table, per ward.checks' own module
docstring).

FAIL DIRECTION -- Ward's row in the suite-wide policy (Courthouse docs/FAIL-DIRECTION.md).
Ward fails CLOSED on everything: malformed input, a check that raises, a shim that cannot start.
Not because closed is universally right, but because of what Ward judges. Ward rules on the ACT,
and a dangerous act allowed is not recoverable at the next event or at Stop -- the write landed,
the credential left, the key was accepted. Its siblings judge the STATEMENT (Makoto) and the
SEQUENCE (Gyroscope), where a missed evaluation is recoverable later in the same session, so they
fail open on carriage and stay loud about it. The axis decides the direction; recoverability is the
axis. A plugin does not get to pick by taste, and the three of them no longer differ by accident.

The one thing Ward will NOT do is deny on a fact that is false. That is not a softening of
fail-closed -- a deny whose stated reason is wrong is unactionable, so the agent rewrites code that
was never the problem and the loop does not heal. See `ward.wire` for the measured case: one
non-UTF-8 byte in an otherwise valid Python file used to arrive as a lone surrogate, break
`ast.parse`, and produce a hard deny reading "introduced Python fragment cannot be parsed
independently" about a fragment that parsed fine. Repairing the byte at the boundary keeps the
failure direction exactly where it was and makes the reason true.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from ward import journal, wire
from ward.checks import evaluate


def read_event() -> tuple[dict[str, Any], int]:
    """Parse the hook envelope off stdin. Returns (event, bytes_repaired).

    Bytes, not text: see `ward.wire`. A lone surrogate must never reach a check, because a check
    handed one reports a fact about the encoding while claiming to report one about the action.
    """
    raw, repaired = wire.read_stdin()
    if not raw.strip():
        raise ValueError("empty stdin")
    event = json.loads(raw)
    if not isinstance(event, dict):
        raise ValueError("event is not a JSON object")
    # The other surrogate door: valid UTF-8 bytes whose JSON text carried an unpaired \\uD8xx
    # escape, which json.loads materializes as a real lone surrogate. wire.read_stdin cannot see
    # that one -- the escape is plain ASCII in the raw text -- so the parsed object is scrubbed too.
    event, escaped = wire.scrub(event)
    return event, repaired + escaped


def emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload))


def deny(reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}


def route(event: dict[str, Any]) -> dict[str, Any]:
    if event.get("hook_event_name") != "PreToolUse":
        return {}
    journal.note_session(event)
    fired = evaluate(event)
    if fired is None:
        return {}
    check_id, message = fired
    # `ward.` prefix on the wire AND `plugin: "ward"` in the journal row. Three plugins register
    # PreToolUse `*` and the host does not say which one denied; the prefix is what lets a user
    # reading the transcript name the author, and the row is what lets it be joined afterwards.
    journal.note_deny(event, check_id, message)
    return deny(f"{check_id}: {message}")


def main() -> int:
    try:
        event, repaired = read_event()
    except ValueError as e:
        journal.note_fault({}, "unreadable_event", str(e), failed_closed=True)
        print(f"ward.dispatch: {e}", file=sys.stderr)
        emit(deny(
            "ward: malformed hook input; failing closed because the pending action could not be "
            "inspected (see dispatch stderr)."
        ))
        return 0
    if repaired:
        # Recorded, and NOT a fault: the event was evaluated, on a repaired payload. Conflating the
        # two would inflate the count of unevaluated calls, which is the number this log exists to
        # keep honest.
        journal.note_repair(event, repaired)
    try:
        result = route(event)
    except Exception as e:
        # route() raising is always a Ward wiring bug, never external data. Loud to stderr; fail
        # CLOSED here, as with malformed-input failure above — a security gate that
        # silently vanishes when its own machinery errors was never a gate, matching Detent's own
        # outbound-gate failure-direction precedent.
        journal.note_fault(event, "check_raised", f"{type(e).__name__}: {e}", failed_closed=True)
        print(f"ward.dispatch: check raised {e!r}", file=sys.stderr)
        if event.get("hook_event_name") == "PreToolUse":
            emit(deny(
                "ward: internal error while a safety check was due to run; failing closed "
                "(see dispatch stderr). Retry the call; report if it persists."
            ))
            return 0
        emit({})
        return 0
    emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

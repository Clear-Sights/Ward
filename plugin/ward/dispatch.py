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
import os
import sys
from typing import Any

from ward import journal, wire
from ward.checks import evaluate


def read_event() -> tuple[dict[str, Any], int, int]:
    """Parse the hook envelope off stdin. Returns (event, undecodable_bytes, escaped_surrogates).

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
    # Returned SEPARATELY, never summed: one counts undecodable bytes, the other counts surrogate
    # escapes that were valid ASCII on the wire. See `journal.note_repair`.
    return event, repaired, escaped


def emit(payload: dict[str, Any]) -> bool:
    """Write the decision to stdout. Returns False iff the write could not be completed.

    GUARDED for the mirror reason `_warn` is, with the OPPOSITE recovery. `_warn` carries a
    diagnostic, so losing it is cheap and it swallows. This carries the VERDICT, so losing it is the
    refusal not being delivered -- and an unhandled `OSError` here (a full disk, `>/dev/full`, EPIPE
    on the first byte) escaped `_run` AND `main`, killed the process with a traceback, and left the
    host reading exit 1. For PreToolUse a nonzero exit other than 2 is a non-blocking error, i.e.
    ALLOW. So the one write Ward cannot afford to lose was exactly the write whose loss turned a
    fail-closed deny into a pass. Callers convert False into the closed exit instead.

    Flushed inside the guard on purpose: without it the write sits in the buffer and fails during
    interpreter shutdown, far outside any handler, which is the same crash one layer later.
    """
    try:
        sys.stdout.write(json.dumps(payload))
        sys.stdout.flush()
        return True
    except Exception:
        return False


def deny(reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}


def _warn(text: str) -> bool:
    """Write one diagnostic line to stderr, swallowing the failure if that write fails.

    GUARDED, and it has to be: every caller is a fail-closed handler that reports between the fault
    it recorded and the deny it is about to emit. Unguarded, this print sat there naked -- an
    unwritable stderr (a closed fd, a full disk, `2>/dev/full`) raised here, the deny below never
    ran, and the hook exited 1 with an empty stdout. That is fail-OPEN produced by an OBSERVABILITY
    failure, in the one plugin whose whole premise is that it never fails open. Reporting must never
    outrank deciding, and one helper is what stops the next handler re-opening the hole with a bare
    `print`.

    Returns True iff the diagnostic actually landed, so a caller never tells the user to go read a
    stderr line that was never written -- a deny must not rest on a false fact, including a false
    fact about itself.

    The `sys.stderr is None` arm is not defensive noise: CPython sets `sys.stderr` to None when fd 2
    is CLOSED (`2>&-`), and `print(file=None)` does not no-op, it targets STDOUT. That spliced this
    diagnostic in front of the JSON object the host parses -- `ward.dispatch: JSONDecodeError...`
    followed by the deny -- which no host can read, so the deny was lost by the very line written to
    explain it. Reporting must never outrank deciding.
    """
    if sys.stderr is None:
        return False
    try:
        print(text, file=sys.stderr)
        return True
    except Exception:
        return False


_WIRE_LOST_EXIT = 2   # PreToolUse: exit 2 is the host's blocking error, and stderr reaches the agent.


def _emit_or_closed(payload: dict[str, Any]) -> int:
    """Write `payload`, and pick the exit status that preserves its MEANING if the write is lost.

    A lost DENY must not read as a pass, so it falls back to exit 2 -- the host's blocking error and
    the only channel left once stdout is gone. A lost `{}` needs no fallback: "no opinion" and "no
    output" are the same answer to the host, and failing closed there would invent a refusal Ward
    never made. Fail closed on the decision, not on the silence.
    """
    if emit(payload):
        return 0
    if not payload:
        return 0
    _warn("ward.dispatch: could not write the decision to stdout; exiting closed.")
    return _WIRE_LOST_EXIT


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


def _mute_unwritable_stderr() -> None:
    """Flush stderr while its failure can still be caught, and retire it if it is broken.

    CPython flushes `sys.stderr` during shutdown, AFTER this hook has returned, and a flush that
    fails there can set the process exit status regardless of what the hook decided. The host then
    reads a crashed hook rather than a decision -- an unwritable stderr downgrading a fail-closed
    refusal into no answer at all, which is the unguarded-`print` defect below one layer further
    out: reporting must never outrank deciding.

    HONEST LIMIT, stated because the alternative is a comment that overclaims: CI reported exit 120
    on 3.12/3.13/3.14 for the deep-input case, and that exact status could NOT be reproduced here
    on 3.11, 3.12 or 3.13 -- the same invocation exits 0 locally with or without this function. So
    this is a mitigation for a mechanism whose trigger is not fully pinned down, not a fix proven
    against a reproduction. What IS verified on all three interpreters is the property the test
    now asserts: the deny reaches stdout. The exit status under a deliberately unwritable stderr is
    CPython shutdown behaviour and is not Ward's to guarantee.
    """
    try:
        sys.stderr.flush()
    except Exception:
        try:
            sys.stderr = open(os.devnull, "w")
        except Exception:
            pass


def main() -> int:
    # try/finally rather than a call before each return: every one of `_run`'s exits is a decision
    # already written to stdout, and a shutdown flush must not be able to overwrite any of them.
    try:
        return _run()
    finally:
        _mute_unwritable_stderr()


def _run() -> int:
    try:
        event, repaired, escaped = read_event()
    except Exception as e:
        # `Exception`, NOT `ValueError`, and the difference is a hole straight through the fail
        # direction this whole module is built on. `json.loads` raises `ValueError` for the
        # malformed input it was written for -- but it raises `RecursionError` on a DEEPLY NESTED
        # document, and `wire.scrub` walks the parsed value recursively and raises the same on the
        # same input. Reproduced: 2000 nested arrays on stdin took the `ValueError` arm's escape,
        # crashed out of `main()`, and the hook exited 1 having written NOTHING to stdout. A hook
        # that emits no decision is a hook that allowed the call, so the one input shaped to be
        # expensive to parse was the one input Ward did not rule on -- fail-OPEN, in the plugin
        # whose entire premise is that it never does that. Anything read_event can raise is an
        # envelope Ward could not inspect, and every one of them takes the same closed exit.
        journal.note_fault({}, "unreadable_event", f"{type(e).__name__}: {e}", failed_closed=True)
        # Via `_warn`, and it has to be: this print sat between the fault and the deny,
        # unprotected, and an unwritable stderr raised here took the deny down with it -- the same
        # defect this handler was written to close, one line lower down. See `_warn`.
        landed = _warn(f"ward.dispatch: {type(e).__name__}: {e}")
        # The pointer is conditional because the line it points at is: `_warn` swallows an
        # unwritable stderr, and a deny that says "see dispatch stderr" when nothing reached stderr
        # asserts a fact that is false, in the module whose rule is that a deny never does that.
        seen = " (see dispatch stderr)" if landed else ""
        return _emit_or_closed(deny(
            "ward: malformed hook input; failing closed because the pending action could not be "
            f"inspected{seen}."
        ))
    if repaired or escaped:
        # Recorded, and NOT a fault: the event was evaluated, on a repaired payload. Conflating the
        # two would inflate the count of unevaluated calls, which is the number this log exists to
        # keep honest.
        journal.note_repair(event, repaired, escaped=escaped)
    try:
        result = route(event)
    except Exception as e:
        # route() raising is always a Ward wiring bug, never external data. Loud to stderr; fail
        # CLOSED here, as with malformed-input failure above — a security gate that
        # silently vanishes when its own machinery errors was never a gate, matching Detent's own
        # outbound-gate failure-direction precedent.
        journal.note_fault(event, "check_raised", f"{type(e).__name__}: {e}", failed_closed=True)
        # Guarded for the same reason as the handler above: an unwritable stderr must not be able
        # to stop the deny underneath it from reaching the wire. See `_warn`.
        landed = _warn(f"ward.dispatch: check raised {e!r}")
        seen = " (see dispatch stderr)" if landed else ""
        if event.get("hook_event_name") == "PreToolUse":
            return _emit_or_closed(deny(
                "ward: internal error while a safety check was due to run; failing closed"
                f"{seen}. Retry the call; report if it persists."
            ))
        return _emit_or_closed({})
    return _emit_or_closed(result)


if __name__ == "__main__":
    raise SystemExit(main())

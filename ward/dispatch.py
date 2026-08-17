"""The pivot. One PreToolUse hook entrypoint: read the event, run it through ward.checks.evaluate,
deny with the first firing check's message, or emit {} (no opinion — every one of these 11 checks
is an unconditional hard block, so there is no rewrite/advisory/defer shape to express; a future
check that needs one of those does not belong in this table, per ward.checks' own module
docstring)."""
from __future__ import annotations

import json
import sys
from typing import Any

from ward.checks import evaluate


def read_event() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        raise ValueError("empty stdin")
    event = json.loads(raw)
    if not isinstance(event, dict):
        raise ValueError("event is not a JSON object")
    return event


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
    fired = evaluate(event)
    if fired is None:
        return {}
    check_id, message = fired
    return deny(f"{check_id}: {message}")


def main() -> int:
    try:
        event = read_event()
    except ValueError as e:
        print(f"ward.dispatch: {e}", file=sys.stderr)
        emit(deny(
            "ward: malformed hook input; failing closed because the pending action could not be "
            "inspected (see dispatch stderr)."
        ))
        return 0
    try:
        result = route(event)
    except Exception as e:
        # route() raising is always a Ward wiring bug, never external data. Loud to stderr; fail
        # CLOSED here, as with malformed-input failure above — a security gate that
        # silently vanishes when its own machinery errors was never a gate, matching Detent's own
        # outbound-gate failure-direction precedent.
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

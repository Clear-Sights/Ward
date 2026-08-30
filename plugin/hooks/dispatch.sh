#!/usr/bin/env bash
# Plugin shim: the only bridge between hooks.json and the package. cd-pinned to the plugin
# root: `python3 -m` puts its cwd FIRST on sys.path -- ahead of PYTHONPATH -- so under the
# former PYTHONPATH form a stray ward/ directory in the session's working tree shadowed the
# plugin package and every check silently vanished (repro pinned by
# tests/test_dispatch_shim.py). Running from the plugin root makes the plugin's own package
# the first candidate instead. Failure direction matches ward.dispatch's own internal-error
# precedent: a gate whose machinery cannot even start fails CLOSED, never silently open --
# an unusable CLAUDE_PLUGIN_ROOT is a Ward wiring bug, exactly like route() raising.
# NB: a bare `cd ""` succeeds in bash, so the empty/unset case needs its own test. A valid but
# incorrect directory is equally unusable; verify the dispatcher exists before invoking Python.
deny_startup() {
  echo "ward dispatch.sh: could not start the Ward dispatcher -- failing closed" >&2
  printf '%s' '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "ward: hook shim could not start the dispatcher; failing closed (see dispatch stderr). Fix the ward plugin install; annotate nothing -- this is a wiring failure, not a check."}}'
  exit 0
}
if [ -z "${CLAUDE_PLUGIN_ROOT:-}" ] || ! cd "$CLAUDE_PLUGIN_ROOT" 2>/dev/null \
    || [ ! -f ward/dispatch.py ]; then
  deny_startup
fi
# WARD_PYTHON names the interpreter when it is not called `python3` on this host. Without it,
# such a host gets `command -v python3` failing and Ward denying every tool call -- the right
# direction for a gate and a useless machine, fixable only by editing a shipped file. Ported by
# shape from `Causality:hooks/dispatch.sh`; the failure DIRECTION is deliberately not ported,
# because that shim fails open by design. An override naming a missing or broken interpreter
# still fails closed here, so this can never be a way to turn Ward off. One executable, no
# arguments: it is passed as a single word so a value carrying flags fails closed rather than
# word-splitting into something unintended.
if ! command -v "${WARD_PYTHON:-python3}" >/dev/null 2>&1; then
  deny_startup
fi
if ! output=$("${WARD_PYTHON:-python3}" -m ward.dispatch); then
  deny_startup
fi
printf '%s' "$output"

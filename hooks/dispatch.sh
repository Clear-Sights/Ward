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
if ! command -v python3 >/dev/null 2>&1; then
  deny_startup
fi
if ! output=$(python3 -m ward.dispatch); then
  deny_startup
fi
printf '%s' "$output"

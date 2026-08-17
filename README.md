# Ward — 11 exact PreToolUse denials

Ward is a Python plugin that blocks eleven dangerous tool-call shapes before execution: protected
path writes, weakened token/certificate/host-key checks, timing-unsafe secret comparison, and
outbound credential patterns. It denies the first match and names the rule and safer retry.

## Scope

- Ward scans newly introduced Python text in `.py` Write/Edit/MultiEdit calls; it does not rescan
  unchanged surrounding source.
- It refuses a recognized mutation when its required path or introduced text is missing.
- NotebookEdit receives the lexical path check, but its cell text does not enter the seven Python
  AST checks.
- An empty response means only that no exact predicate matched. It is not an approval or proof
  that a later filesystem or network operation is safe.

The complete security boundary and known reachable bypasses are in [SECURITY.md](SECURITY.md).

## Run it

Run the shipped hook from the plugin root with a complete PreToolUse event:

```console
$ printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/etc/ward-smoke","content":"x"},"cwd":"/tmp"}' | CLAUDE_PLUGIN_ROOT="$PWD" hooks/dispatch.sh
```

The JSON response contains `permissionDecision: "deny"`; the shell exits normally because the host
reads that protocol response and cancels the action. Run the full suite with:

```console
$ python -m unittest discover -s tests
```

## Design

`hooks/hooks.json` registers the shell entry point for PreToolUse. The shell shim changes into the
plugin root before invoking the Python dispatcher, so a package with the same name in the caller's
working directory cannot shadow Ward's own checks. If the shim cannot start the dispatcher, it
returns a deny rather than making the gate disappear.

The dispatcher reads one JSON event, applies the ordered `CHECKS` table, and emits one JSON result.
Seven checks parse introduced Python AST; the remaining checks inspect lexical paths, serialized
outbound payloads, or the introduced-versus-removed mutation text. Keeping those mechanisms
separate avoids claiming coverage they do not have.

## Install

Add this checkout as a Claude marketplace, then install the plugin:

```console
$ claude plugin marketplace add /path/to/ward
$ claude plugin install ward@ward --scope user
```

Claude supplies `CLAUDE_PLUGIN_ROOT` when it invokes the registered hook. The smoke command above
drives the same bridge without modifying a real file.

## Contributing

Keep a check narrow, add firing and clean cases, and exercise the shell entry point when changing
hook wiring. Do not strengthen the documented path guarantee without moving containment into the
writer.

## License

See [LICENSE](LICENSE).

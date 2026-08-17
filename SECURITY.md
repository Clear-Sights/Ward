# Ward security model

## Guarantee

Ward is a policy filter over a `PreToolUse` event. When a Ward predicate returns a deny and the
Claude Code host honors it, that submitted tool call is canceled. When Ward returns no finding, the
only conclusion is that the inspected JSON event matched none of Ward's predicates.

Ward is **not a filesystem confinement boundary or reference monitor**:

- `forbidden_location` lexically normalizes the path string and compares it with the event's `cwd`.
  It does not resolve symlinks, inspect mounts, or open the target.
- The writer resolves the pathname separately after Ward returns, when filesystem state may differ.
- Other write routes and kernel filesystem operations are outside this predicate.

An allowed event therefore does not prove that the later write will land inside `cwd`.

## Named non-claims for the eleven exact predicates

Each identifier below names an observed bypass that Ward deliberately does not claim to catch. An
allow for one of these shapes means only that no exact Ward predicate matched; it is never a safety
verdict.

- `forbidden_location.symlink_resolution`: an in-cwd lexical pathname can resolve outside `cwd`
  when a symlink is changed after Ward returns; the measurement below exercises this check/use gap.
- `timing_unsafe_compare.getattr_digest`: `getattr(digest, "hexdigest")() == supplied` is not a
  direct visible `digest()`/`hexdigest()` AST call and is not resolved through indirection.
- `jwt_none_alg.variable_allowlist`: `jwt.decode(..., algorithms=allowed)` is not inspected when
  `allowed` is a variable whose value could contain `"none"`.
- `jwt_signature_disabled.variable_options`: `jwt.decode(..., options=options)` is not inspected
  when `options` is a variable whose value could disable `verify_signature`.
- `cert_verify_disabled.import_alias`: an aliased TLS client call such as `net_get(...,
  verify=False)` is not resolved back to `requests.get`.
- `cert_reqs_none.variable_value`: `cert_reqs=disabled` is not resolved when `disabled` holds
  `ssl.CERT_NONE`.
- `cert_none_mode.variable_value`: `context.verify_mode = disabled` is not resolved when
  `disabled` holds `ssl.CERT_NONE`.
- `paramiko_host_key_weakened.policy_alias`: an alias such as `policy = paramiko.AutoAddPolicy`
  is not resolved before `set_missing_host_key_policy(policy())`.
- `outbound_secret_pattern.percent_encoded_token`: payload scanning matches raw credential
  grammars only; a percent-encoded token such as `ghp%5f...` is not decoded before matching.
- `self_mute_guard.indirect_callable`: removal through an alias or dynamically constructed name is
  not resolved back to an integrity/verifier-named callable.
- `integrity_suppression_flag.indirect_env_name`: an environment-variable name assembled at runtime
  is not reconstructed and matched as an integrity suppression gate.

## Reproduce the check/use limit

`tests/test_path_reliability.py` makes the check/use boundary cooperative and repeatable. For each
trial it points an in-workspace symlink at an in-workspace directory, asks Ward to validate a path
through that link, changes the link to an outside directory after Ward returns, and performs the
simulated write through the unchanged pathname.

Run it with:

```console
$ python -m unittest discover -s tests -p 'test_path_reliability.py'
Ward path reliability: 1000/1000 allowed validations wrote outside cwd (100.0% disagreement)
.
----------------------------------------------------------------------
Ran 1 test in <elapsed>s

OK
```

`<elapsed>` is machine-specific. The cooperative measurement performs the filesystem write after
Ward returns and must report 1,000/1,000 disagreements. It demonstrates a structural limit, not the
probability of winning a scheduler race.

## Required host boundary

Containment belongs in the process that opens or creates the file, or in a kernel policy applied to
that process:

- Open the permitted root as a stable directory descriptor or handle.
- Convert the accepted target to a relative path under that root.
- Resolve and create/open through the root, then write through the returned descriptor without
  reopening the original pathname.

On Linux, `openat2(dirfd, relative_path, ...)` with `RESOLVE_BENEATH` and explicit
`RESOLVE_NO_MAGICLINKS` performs the containment decision during the open/create operation.
`RESOLVE_NO_SYMLINKS` can additionally reject all symlinks. `O_PATH` directory descriptors and the
fd-relative `*at()` family provide stable object references for subsequent operations.

- [`openat2(2)` resolution restrictions](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [Landlock access control](https://docs.kernel.org/userspace-api/landlock.html)

The current `PreToolUse` contract returns a decision and may replace JSON input; it does not return
a writer-owned file descriptor. Replacing one pathname string with another still leaves resolution
to the writer.

- [Claude Code `PreToolUse` input and decision schema](https://code.claude.com/docs/en/hooks#pretooluse)

The file-tool host—not Ward—must therefore provide containment. Ward's denial is an early policy
signal, not proof of where an allowed write will land.

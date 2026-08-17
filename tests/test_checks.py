"""Parity tests: one FIRE case and one CLEAN-PASS case per check, ported from each source check's
own docstring fire-examples in Makoto/Detent (not invented from scratch) — a security regression
here is a real vulnerability-detection gap, not a refactor risk, so these mirror the exact shapes
the original checks were built to catch."""
from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from ward.checks import CHECKS, evaluate


def _pre(tool_name: str, tool_input: dict, cwd: str = "/workspace/repo") -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": tool_name, "tool_input": tool_input, "cwd": cwd}


def _write(content: str, file_path: str = "/workspace/repo/mod.py") -> dict:
    return _pre("Write", {"file_path": file_path, "content": content})


def _edit(new_string: str, file_path: str = "/workspace/repo/mod.py") -> dict:
    return _pre("Edit", {"file_path": file_path, "old_string": "pass", "new_string": new_string})


def _test_table_has_11_rows():
    assert len(CHECKS) == 11
    assert len(set(row[0] for row in CHECKS)) == 11  # every id unique


# --- forbidden_location --------------------------------------------------------------------------

def _test_forbidden_location_fires_on_protected_dir():
    fired = evaluate(_write("x = 1\n", file_path="/etc/passwd"))
    assert fired is not None and fired[0] == "ward.forbidden_location"


def _test_forbidden_location_clean_on_cwd_file():
    assert evaluate(_write("x = 1\n", file_path="/workspace/repo/mod.py")) is None


def _test_forbidden_location_clean_on_system_named_directory_inside_cwd():
    assert evaluate(_write("x = 1\n", file_path="/workspace/repo/dev/settings.py")) is None


def _test_forbidden_location_handles_windows_path_separators():
    fired = evaluate(_pre(
        "Write",
        {"file_path": r"C:\workspace\repo\.ssh\config", "content": "Host example\n"},
        cwd=r"C:\workspace\repo",
    ))
    assert fired is not None and fired[0] == "ward.forbidden_location"


def _test_forbidden_location_detects_windows_cwd_escape():
    fired = evaluate(_pre(
        "Write",
        {"file_path": r"C:\workspace\outside\file.txt", "content": "x\n"},
        cwd=r"C:\workspace\repo",
    ))
    assert fired is not None and fired[0] == "ward.forbidden_location"


def _test_forbidden_location_allows_windows_path_inside_cwd_case_insensitively():
    assert evaluate(_pre(
        "Write",
        {"file_path": r"c:\WORKSPACE\REPO\src\file.txt", "content": "x\n"},
        cwd=r"C:\workspace\repo",
    )) is None


def _test_forbidden_location_refuses_unc_share_crossing_and_drive_relative_paths():
    cases = (
        _pre(
            "Write",
            {"file_path": r"\\host\other\..\share\file.txt", "content": "x\n"},
            cwd=r"\\host\share",
        ),
        _pre(
            "Write",
            {"file_path": r"C:secret.txt", "content": "x\n"},
            cwd=r"D:\repo",
        ),
    )
    for event in cases:
        fired = evaluate(event)
        assert fired is not None, "an ambiguous Windows pathname must not be admitted"
        assert fired[0] == "ward.forbidden_location"
        assert "outside the working directory" in fired[1]


def _test_forbidden_location_does_not_recommend_inapplicable_line_exemption():
    fired = evaluate(_write("x = 1\n", file_path="/etc/ward.conf"))
    assert fired is not None
    assert "ward-allow" not in fired[1]


def _test_forbidden_location_honours_configured_plan_home():
    # `unittest.mock.patch.dict` rather than pytest's monkeypatch: same guarantee that the
    # variable is restored however the test exits, and it is in the standard library.
    with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/var/lib/claude-test"}):
        _assert_configured_plan_home_is_honoured()


def _assert_configured_plan_home_is_honoured():
    assert evaluate(_write(
        "plan\n", file_path="/var/lib/claude-test/plans/implementation.md"
    )) is None
    default_plan = Path.home() / ".claude" / "plans" / "implementation.md"
    fired = evaluate(_write("plan\n", file_path=str(default_plan)))
    assert fired is not None and fired[0] == "ward.forbidden_location"


def _test_forbidden_location_fires_when_editing_credential_basename():
    fired = evaluate(_edit("token = replacement\n", file_path="/workspace/repo/credentials"))
    assert fired is not None and fired[0] == "ward.forbidden_location"


def _test_forbidden_location_fires_when_notebook_edit_targets_credential_basename():
    fired = evaluate(_pre("NotebookEdit", {"notebook_path": "/workspace/repo/.netrc"}))
    assert fired is not None and fired[0] == "ward.forbidden_location"


# --- timing_unsafe_compare ------------------------------------------------------------------------

def _test_timing_unsafe_compare_fires():
    fired = evaluate(_write("if computed.hexdigest() == provided:\n    pass\n"))
    assert fired is not None and fired[0] == "ward.timing_unsafe_compare"


def _test_timing_unsafe_compare_clean_with_compare_digest():
    assert evaluate(_write("if hmac.compare_digest(computed.hexdigest(), provided):\n    pass\n")) is None


def _test_timing_unsafe_compare_clean_on_polysemous_word():
    # config_key == expected_key is an honest non-secret compare (no STRONG token) — must stay silent
    assert evaluate(_write("if config_key == expected_key:\n    pass\n")) is None


def _test_timing_unsafe_compare_fires_on_unsafe_pair_before_sentinel_pair():
    fired = evaluate(_write("if computed.hexdigest() == provided != None:\n    pass\n"))
    assert fired is not None and fired[0] == "ward.timing_unsafe_compare"


def _test_timing_unsafe_compare_fires_on_unsafe_pair_in_mixed_chain():
    fired = evaluate(_write("if computed.hexdigest() == provided < limit:\n    pass\n"))
    assert fired is not None and fired[0] == "ward.timing_unsafe_compare"


def _test_timing_unsafe_compare_clean_on_direct_sentinel_comparison():
    assert evaluate(_write("if computed.hexdigest() != None:\n    pass\n")) is None


# --- jwt_none_alg ----------------------------------------------------------------------------------

def _test_jwt_none_alg_fires():
    fired = evaluate(_write('jwt.decode(token, key, algorithms=["HS256", "none"])\n'))
    assert fired is not None and fired[0] == "ward.jwt_none_alg"


def _test_jwt_none_alg_clean_with_real_algorithm():
    assert evaluate(_write('jwt.decode(token, key, algorithms=["RS256"])\n')) is None


def _test_jwt_none_alg_guidance_cites_the_applicable_standard():
    fired = evaluate(_write('jwt.decode(token, key, algorithms=["none"])\n'))
    assert fired is not None
    assert "RFC 8725" in fired[1]
    assert "CVE-2022-29217" not in fired[1]


# --- jwt_signature_disabled ------------------------------------------------------------------------

def _test_jwt_signature_disabled_fires_on_verify_false():
    fired = evaluate(_write("jwt.decode(token, key, verify=False)\n"))
    assert fired is not None and fired[0] == "ward.jwt_signature_disabled"


def _test_jwt_signature_disabled_fires_on_options_dict():
    fired = evaluate(_write('jwt.decode(token, key, options={"verify_signature": False})\n'))
    assert fired is not None and fired[0] == "ward.jwt_signature_disabled"


def _test_jwt_signature_disabled_fires_on_dict_constructor_options():
    fired = evaluate(_write(
        "jwt.decode(token, key, options=dict(verify_signature=False))\n"
    ))
    assert fired is not None and fired[0] == "ward.jwt_signature_disabled"


def _test_jwt_signature_disabled_clean_when_verified():
    assert evaluate(_write("jwt.decode(token, key, algorithms=['RS256'])\n")) is None


# --- cert_verify_disabled --------------------------------------------------------------------------

def _test_cert_verify_disabled_fires_on_requests_verify_false():
    fired = evaluate(_write("requests.get(url, verify=False)\n"))
    assert fired is not None and fired[0] == "ward.cert_verify_disabled"


def _test_cert_verify_disabled_fires_on_unverified_context():
    fired = evaluate(_write("ctx = ssl._create_unverified_context()\n"))
    assert fired is not None and fired[0] == "ward.cert_verify_disabled"


def _test_cert_verify_disabled_fires_on_annotated_check_hostname_assignment():
    fired = evaluate(_write("ctx.check_hostname: bool = False\n"))
    assert fired is not None and fired[0] == "ward.cert_verify_disabled"


def _test_cert_verify_disabled_clean_on_unrelated_verify_kwarg():
    # form.clean(verify=False) is not a TLS callee — must stay silent (FP-safety was load-bearing)
    assert evaluate(_write("form.clean(verify=False)\n")) is None


def _test_cert_verify_disabled_clean_when_library_name_is_only_a_substring():
    assert evaluate(_write("form.myrequests(verify=False)\n")) is None


def _test_cert_verify_disabled_still_fires_on_underscored_session_alias():
    fired = evaluate(_write("requests_session.get(url, verify=False)\n"))
    assert fired is not None and fired[0] == "ward.cert_verify_disabled"


def _test_cert_verify_disabled_clean_when_verified():
    assert evaluate(_write("requests.get(url, verify=True)\n")) is None


# --- cert_reqs_none ----------------------------------------------------------------------------------

def _test_cert_reqs_none_fires():
    fired = evaluate(_write("ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)\n"))
    assert fired is not None and fired[0] == "ward.cert_reqs_none"


def _test_cert_reqs_none_clean_when_required():
    assert evaluate(_write("ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED)\n")) is None


def _test_cert_reqs_none_clean_on_unrelated_function():
    assert evaluate(_write("render(cert_reqs=CERT_NONE)\n")) is None


# --- cert_none_mode ----------------------------------------------------------------------------------

def _test_cert_none_mode_fires():
    fired = evaluate(_write("ctx.verify_mode = ssl.CERT_NONE\n"))
    assert fired is not None and fired[0] == "ward.cert_none_mode"


def _test_cert_none_mode_fires_on_annotated_assignment():
    fired = evaluate(_write("ctx.verify_mode: ssl.VerifyMode = ssl.CERT_NONE\n"))
    assert fired is not None and fired[0] == "ward.cert_none_mode"


def _test_cert_none_mode_clean_on_comparison():
    # `if mode == CERT_NONE:` is a comparison, not an assignment — must stay silent (FP guard)
    assert evaluate(_write("if mode == ssl.CERT_NONE:\n    pass\n")) is None


# --- paramiko_host_key_weakened ------------------------------------------------------------------------

def _test_paramiko_host_key_weakened_fires_on_autoadd():
    fired = evaluate(_write("client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"))
    assert fired is not None and fired[0] == "ward.paramiko_host_key_weakened"


def _test_paramiko_host_key_weakened_fires_on_keyword_policy():
    fired = evaluate(_write(
        "client.set_missing_host_key_policy(policy=paramiko.AutoAddPolicy())\n"
    ))
    assert fired is not None and fired[0] == "ward.paramiko_host_key_weakened"


def _test_paramiko_host_key_weakened_names_warning_policy_correctly():
    fired = evaluate(_write("client.set_missing_host_key_policy(paramiko.WarningPolicy())\n"))
    assert fired is not None and "set_missing_host_key_policy(WarningPolicy)" in fired[1]


def _test_paramiko_host_key_weakened_clean_on_reject_policy():
    assert evaluate(_write("client.set_missing_host_key_policy(paramiko.RejectPolicy())\n")) is None


# --- outbound_secret_pattern -----------------------------------------------------------------------

def _test_outbound_secret_pattern_fires_on_webfetch():
    fired = evaluate(_pre("WebFetch", {"url": "https://x/?tok=ghp_" + "a" * 36}))
    assert fired is not None and fired[0] == "ward.outbound_secret_pattern"


def _test_outbound_secret_pattern_fires_on_aws_temporary_access_key():
    fired = evaluate(_pre("WebFetch", {"url": "https://x/?key=ASIA" + "A" * 16}))
    assert fired is not None and fired[0] == "ward.outbound_secret_pattern"


def _test_outbound_secret_pattern_clean_on_local_tool():
    # Bash/Edit/Write are not WORLD-class — a secret in a local edit is legitimate rotation work
    assert evaluate(_write("TOKEN = 'ghp_" + "a" * 36 + "'\n")) is None


def _test_outbound_secret_pattern_clean_on_mcp_with_no_secret():
    assert evaluate(_pre("mcp__github__create_pull_request", {"title": "fix bug"})) is None


def _test_outbound_secret_pattern_ignores_non_pretooluse_events():
    event = _pre("WebFetch", {"url": "https://x/?tok=ghp_" + "a" * 36})
    event["hook_event_name"] = "PostToolUse"
    assert evaluate(event) is None


# --- self_mute_guard -----------------------------------------------------------------------------

def _test_self_mute_guard_catches_planted_verifier_removal():
    event = _pre("Edit", {
        "file_path": "/workspace/repo/policy.py",
        "old_string": "result = run_integrity_verifier(payload)\n",
        "new_string": "result = True\n",
    })
    fired = evaluate(event)
    assert fired is not None and fired[0] == "ward.self_mute_guard"


def _test_self_mute_guard_negative_plant_depends_on_removed_input():
    event = _pre("Edit", {
        "file_path": "/workspace/repo/policy.py",
        "old_string": "result = run_integrity_verifier(payload)\n",
        "new_string": "result = True\n",
    })
    assert evaluate(event) is not None, "planted removal must exercise the check"
    event["tool_input"]["old_string"] = "result = old_value\n"
    assert evaluate(event) is None, "removing the planted check input must remove the denial"


# --- integrity_suppression_flag ------------------------------------------------------------------

def _test_integrity_suppression_flag_catches_planted_env_gate():
    event = _write(
        'if not os.getenv("SKIP_AUDIT_VERIFICATION"):\n    verify_integrity(payload)\n',
        file_path="/workspace/repo/audit.py",
    )
    fired = evaluate(event)
    assert fired is not None and fired[0] == "ward.integrity_suppression_flag"


def _test_integrity_suppression_flag_negative_plant_depends_on_introduced_input():
    event = _write("integrity_verification_skip = true\n", file_path="/workspace/repo/policy.toml")
    assert evaluate(event) is not None, "planted suppression must exercise the check"
    event["tool_input"]["content"] = "integrity_verification_enabled = true\n"
    assert evaluate(event) is None, "removing the planted suppression must remove the denial"


# --- ward-allow escape hatch (AST-scaffolded checks only) --------------------------------------------

def _test_ward_allow_suppresses_ast_scaffolded_check():
    content = "jwt.decode(token, key, verify=False)  # ward-allow: test fixture decodes an unsigned token\n"
    assert evaluate(_write(content)) is None


def _test_bare_ward_allow_does_not_suppress():
    content = "jwt.decode(token, key, verify=False)  # ward-allow\n"
    fired = evaluate(_write(content))
    assert fired is not None and fired[0] == "ward.jwt_signature_disabled"


# --- non-.py files never trigger the AST-scaffolded 7 --------------------------------------------------

def _test_ast_scaffolded_checks_ignore_non_python_files():
    assert evaluate(_write("verify=False\n", file_path="/workspace/repo/notes.txt")) is None


# --- first-match-wins table order sanity -----------------------------------------------------------

def _test_evaluate_returns_none_on_clean_event():
    assert evaluate(_write("def add(a, b):\n    return a + b\n")) is None


def _test_evaluate_ignores_non_pretooluse_events():
    assert evaluate({"hook_event_name": "PostToolUse", "tool_name": "Write",
                      "tool_input": {"file_path": "/etc/passwd", "content": "x"}}) is None


def _test_write_missing_required_inspection_input_fails_closed():
    complete = _write("requests.get(u, verify=False)\n")
    assert evaluate(complete) is not None  # control: the complete unsafe action is denied

    missing_path = _write("requests.get(u, verify=False)\n")
    del missing_path["tool_input"]["file_path"]
    missing_input = _write("requests.get(u, verify=False)\n")
    del missing_input["tool_input"]

    for event in (missing_path, missing_input):
        fired = evaluate(event)
        assert fired is not None, "a Write Ward cannot inspect must not become an allow"
        assert fired[0] == "ward.cannot_evaluate"
        assert "cannot evaluate" in fired[1]


def _test_empty_required_mutation_input_fails_closed():
    cases = []

    empty_write = _write("")
    cases.append(empty_write)

    empty_edit = {
        "hook_event_name": "PreToolUse", "tool_name": "Edit",
        "tool_input": {"file_path": "/workspace/repo/mod.py", "new_string": ""},
        "cwd": "/workspace/repo",
    }
    cases.append(empty_edit)

    empty_multiedit_list = {
        "hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
        "tool_input": {"file_path": "/workspace/repo/mod.py", "edits": []},
        "cwd": "/workspace/repo",
    }
    cases.append(empty_multiedit_list)

    empty_multiedit_replacement = {
        "hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
        "tool_input": {"file_path": "/workspace/repo/mod.py", "edits": [{"new_string": ""}]},
        "cwd": "/workspace/repo",
    }
    cases.append(empty_multiedit_replacement)

    for event in cases:
        fired = evaluate(event)
        assert fired is not None, "an empty mutation must not become a quiet allow"
        assert fired[0] == "ward.cannot_evaluate"
        assert "cannot evaluate" in fired[1]


def _test_edit_new_string_is_scanned_not_old_string():
    # the edit-content gap: only the INTRODUCED text (new_string) is scanned, never old_string —
    # an agent weakening a verifier via Edit must not evade the scan
    fired = evaluate(_edit("requests.get(url, verify=False)\n"))
    assert fired is not None and fired[0] == "ward.cert_verify_disabled"

    fragment = evaluate(_pre("Edit", {
        "file_path": "/workspace/repo/mod.py",
        "old_string": "verify=True",
        "new_string": "verify=False",
    }))
    assert fragment is not None, "a detached security keyword must not become a clean result"
    assert fragment[0] == "ward.cannot_evaluate"
    assert "fragment" in fragment[1]


def _test_multiedit_scans_each_fragment_independently():
    event = _pre("MultiEdit", {"file_path": "/workspace/repo/mod.py", "edits": [
        {"old_string": "old_a", "new_string": "requests.get(url, verify=False)\n"},
        {"old_string": "old_b", "new_string": "    harmless()\n"},
    ]})
    fired = evaluate(event)
    assert fired is not None and fired[0] == "ward.cert_verify_disabled"


def _test_multiedit_unparseable_fragments_fail_closed_without_joining():
    event = _pre("MultiEdit", {"file_path": "/workspace/repo/mod.py", "edits": [
        {"old_string": "old_a", "new_string": "requests.get("},
        {"old_string": "old_b", "new_string": "url, verify=False)"},
    ]})
    fired = evaluate(event)
    assert fired is not None
    assert fired[0] == "ward.cannot_evaluate"
    assert "cannot be parsed" in fired[1]


# --- ward-allow must be bound to the line it exempts ---------------------------------------------
#
# The marker's whole job is to exempt ONE deliberate line. A scan of the raw introduced text cannot
# tell an annotation from a mention, so any occurrence anywhere in the chunk disarmed every check in
# it -- a security tool defeated by a string literal. Ported from Makoto's own lesson, stated in
# `_primitives.location_match`: "Equality, never substring: 'auth.py' must NOT match
# 'auth_helper.py'."

_UNSAFE = 'import requests\nrequests.get("https://bank.example/transfer", verify=False)\n'


def _test_marker_in_an_unrelated_string_does_not_exempt():
    decoy = 'note = "ward-allow: this string is not an annotation"\n'
    assert evaluate(_write(decoy + _UNSAFE)) is not None, \
        "gate measured nothing -- the check lost its teeth"


def _test_marker_in_a_comment_on_another_line_does_not_exempt():
    decoy = "# ward-allow: this comment annotates nothing on the unsafe line\n"
    assert evaluate(_write(decoy + _UNSAFE)) is not None, \
        "gate measured nothing -- the check lost its teeth"


def _test_marker_on_the_firing_line_still_exempts():
    annotated = ('import requests\n'
                 'requests.get("https://bank.example/transfer", verify=False)'
                 '  # ward-allow: pinned CA is supplied by the caller\n')
    assert evaluate(_write(annotated)) is None


def _test_the_unsafe_control_fires_without_any_marker():
    assert evaluate(_write(_UNSAFE)) is not None


def _test_one_annotated_line_does_not_carry_a_second_unsafe_line():
    """The exemption is per-line, so an annotated line must not launder its neighbours.

    This is the half a chunk-wide bypass hides: even after binding the marker to a line, returning
    on the first exempt match would let one legitimate annotation disarm every other unsafe line in
    the same write. The scaffold continues instead, so the SECOND call still denies.
    """
    content = ('import requests\n'
               'requests.get("https://a.example", verify=False)  # ward-allow: pinned CA supplied\n'
               'requests.get("https://b.example", verify=False)\n')
    fired = evaluate(_write(content))
    assert fired is not None, "gate measured nothing -- the check lost its teeth"
    assert "line 3" in fired[1], fired


def _test_a_marker_inside_a_docstring_does_not_exempt():
    content = ('"""ward-allow: module docstring mentioning the marker"""\n'
               'import requests\n'
               'requests.get("https://bank.example", verify=False)\n')
    assert evaluate(_write(content)) is not None


# --- stdlib discovery ---------------------------------------------------------------------------
#
# Every test above is a private zero-argument function that asserts. Keeping the source callables
# private prevents pytest from collecting them once at module scope and again through this class.
# The adapter gives each exact body its public `test_*` unittest name, so unittest and pytest both
# collect one representation of every security parity test without rewriting the bodies.
class Checks(unittest.TestCase):
    pass


for _name, _fn in sorted(globals().items()):
    if _name.startswith("_test_") and callable(_fn):
        setattr(Checks, _name.removeprefix("_"), staticmethod(_fn))

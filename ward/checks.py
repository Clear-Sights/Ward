"""ward.checks — the third axis: is this ACTION dangerous regardless of intent or honesty.

Not sincerity (Makoto: is the agent's claim honest) and not determination (Detent: is this
acquisition/transport deterministic) — a safety axis. 11 exact, no-substitute, PreToolUse hard
denies, ported by SHAPE (never imported — copy, never a cross-repo dependency) from Detent (1) and
Makoto (10), unified here because they share one real MECHANISM, not a domain: PreToolUse BLOCK,
exact predicate, no judgment, no softer tier.

Design principle (owner correction, 2026-07-13): don't keep a whole check monolithic because ONE
part of it needs bespoke logic — separate the irreducible sliver from the rest, and TABLE the
rest. 7 of these 11 checks share one AST-introduced-scan scaffold (`_ast_introduced_check`); each
supplies only its own small, pure `_xxx_node_match(node) -> str | None` — the genuinely
irreducible per-check logic. The other 4 don't scan introduced Python AST and stay their own small
functions for the same honest reason Detent's own
moves.py keeps dataflow-sharing checks separate — forcing them into the AST scaffold would be
judgment wearing a shared shape's clothes, not a real generalization.
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import textwrap
import tokenize
from pathlib import PurePosixPath
from typing import Any, Callable, Optional

# ================================================================================================
# Shared leaves — the "rest" every AST-based check below tables against instead of repeating.
# ================================================================================================

_WARD_ALLOW_RX = re.compile(r"ward-allow\s*:\s*\S", re.IGNORECASE)
_PY_FILE_RX = re.compile(r"\.py$")
_JWT_CALLEE_RX = re.compile(r"(?i)(?:^|\.)(?:jwt|jose|pyjwt)(?:\.|$)")


def _allow_lines(content: str) -> frozenset[int]:
    """Line numbers carrying a structured `ward-allow: <reason>` marker IN A COMMENT.

    TOKENIZED, never regex-scanned over raw text, and bound to the LINE rather than the chunk.
    Scanning the whole introduced text for the marker is how a security tool gets defeated by a
    string literal: `note = "ward-allow: ..."` on line 1 disarmed every check on every other line,
    because a raw scan cannot tell an annotation from a MENTION. Measured before the fix — a
    `verify=False` call went from DENIED to allowed with one unrelated string added above it, and
    a comment on a different line did the same. That is the same lesson `_parse_introduced` already
    encodes for the checks themselves, and the same one Makoto's `location_match` states outright:
    equality, never substring.

    A bare `ward-allow` with no colon and reason still does not exempt.

    Coordinates match `_parse_introduced`'s: the two parse attempts are mirrored so the returned
    line numbers are directly comparable to `node.lineno - off`. If neither tokenizes, NOTHING is
    exempt -- a check fires rather than being silently disarmed, which is the only safe direction
    for a hard deny.
    """
    dedented = textwrap.dedent(content)
    wrapped = "if True:\n" + "\n".join("    " + ln for ln in dedented.splitlines())
    for source, off in ((dedented, 0), (wrapped, 1)):
        try:
            return frozenset(
                tok.start[0] - off
                for tok in tokenize.generate_tokens(io.StringIO(source).readline)
                if tok.type == tokenize.COMMENT and _WARD_ALLOW_RX.search(tok.string)
            )
        except (tokenize.TokenError, IndentationError, SyntaxError):
            continue
    return frozenset()


def scan_target_contents(tool_input: dict) -> tuple[str, ...]:
    """The NEW text a PreToolUse file-mutation introduces — Write's `content`, Edit's
    `new_string`, or each of MultiEdit's edits' `new_string`s. Never `old_string`: scanning only
    what is being INTRODUCED (not the whole post-edit file, not what's being removed) is what
    keeps Edit false-positive-safe and closes the edit-content gap — an agent inserting a
    weakening via Edit must not evade a scan that only ever looked at Write's `content`.

    MultiEdit fragments stay separate: concatenating unrelated replacements can either make valid
    code unparseable or manufacture a valid AST node that no individual edit introduces."""
    if not isinstance(tool_input, dict):
        return ()
    content = tool_input.get("content")
    if content:
        return (content,)
    new_string = tool_input.get("new_string")
    if new_string:
        return (new_string,)
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        return tuple(e.get("new_string", "") for e in edits
                     if isinstance(e, dict) and e.get("new_string"))
    return ()


def _parse_introduced(content: str):
    """Parse INTRODUCED text into an AST module, fragment-tolerant. Returns (tree, line_offset);
    (None, 0) when unparseable — an unparseable fragment is never confirmed as active code, so a
    check built on this degrades to silent (false-negative-safe) rather than firing on a
    comment/string/docstring MENTION."""
    if not content or not content.strip():
        return None, 0
    dedented = textwrap.dedent(content)
    try:
        return ast.parse(dedented), 0
    except (SyntaxError, ValueError):
        pass
    try:
        body = "\n".join("    " + ln for ln in dedented.splitlines())
        return ast.parse("if True:\n" + body), 1
    except (SyntaxError, ValueError):
        return None, 0


def is_false_const(node) -> bool:
    """True iff `node` is the literal `False` constant."""
    return isinstance(node, ast.Constant) and node.value is False


def is_cert_none(node) -> bool:
    """True iff `node` is `ssl.CERT_NONE` (an Attribute) or a bare `CERT_NONE` Name."""
    if isinstance(node, ast.Attribute) and node.attr == "CERT_NONE":
        return True
    return isinstance(node, ast.Name) and node.id == "CERT_NONE"


def callee_chain(call: ast.Call) -> str:
    """Dotted callee name of a Call — `requests.get`, `jwt.decode`. Descends through an
    intermediate Call so `requests.Session().get(...)` keeps the receiver token."""
    parts: list = []
    f = call.func
    while True:
        if isinstance(f, ast.Attribute):
            parts.append(f.attr)
            f = f.value
        elif isinstance(f, ast.Call):
            f = f.func
        elif isinstance(f, ast.Name):
            parts.append(f.id)
            break
        else:
            break
    return ".".join(reversed(parts))


def assignment_parts(node: ast.AST) -> tuple[tuple[ast.expr, ...], Optional[ast.expr]]:
    """Targets and value for ordinary or annotated assignments."""
    if isinstance(node, ast.Assign):
        return tuple(node.targets), node.value
    if isinstance(node, ast.AnnAssign):
        return (node.target,), node.value
    return (), None


def jwt_decode_callee_chain(node) -> Optional[str]:
    """The callee-chain string iff `node` is an `ast.Call` targeting a jwt/jose `decode` entry
    point (`_JWT_CALLEE_RX` matches the chain AND the chain's tail is literally `decode`); None
    otherwise. Shared precondition gate for both jwt checks below."""
    if not isinstance(node, ast.Call):
        return None
    chain = callee_chain(node)
    if not _JWT_CALLEE_RX.search(chain):
        return None
    if chain.split(".")[-1] != "decode":
        return None
    return chain


def _ast_introduced_check(node_match: Callable[[ast.AST], Optional[str]]) -> Callable[[dict], Optional[str]]:
    """The shared 'rest' every AST-based check in this module tables against: PreToolUse-only,
    `.py`-file-gated, introduced-text-only, ward-allow-exempted, first-matching-node wins. Returns
    check(event) -> reason string | None. Each caller supplies only its own irreducible
    `node_match` — the one part that's genuinely different per check."""
    def _check(event: dict) -> Optional[str]:
        if event.get("hook_event_name") != "PreToolUse":
            return None
        ti = event.get("tool_input")
        if not isinstance(ti, dict):
            return None
        fp = ti.get("file_path", "")
        if not isinstance(fp, str) or not _PY_FILE_RX.search(fp):
            return None
        for content in scan_target_contents(ti):
            tree, off = _parse_introduced(content)
            if tree is None:
                continue
            exempt = _allow_lines(content)
            for node in ast.walk(tree):
                label = node_match(node)
                if label:
                    line_no = max(1, getattr(node, "lineno", 1) - off)
                    # `continue`, never `return None`: one annotated line is one exemption. Stopping
                    # here would let a single legitimate marker carry every other unsafe line in the
                    # same write, which is the chunk-wide bypass this function was rewritten to close.
                    if line_no in exempt:
                        continue
                    return f"{label} at line {line_no}"
        return None
    return _check


# ================================================================================================
# The 7 irreducible per-check node-match predicates (ported verbatim by SHAPE from Makoto).
# ================================================================================================

# --- ward.timing_unsafe_compare -----------------------------------------------------------------
_STRONG_RX = re.compile(
    r"(?i)(?:^|_)(hmac|hexdigest|signature|csrf|otp|totp|hotp|passphrase|nonce)(?:$|_)"
)
_METADATA_SUFFIX_RX = re.compile(
    r"(?i)_(size|len|length|type|name|algorithm|algo|id|field|header|count|index|idx"
    r"|version|format|kind|class|mode|status|state|prefix|suffix|expiry|ttl|url|uri|path)$"
)
_DIGEST_METHODS = frozenset({"hexdigest", "digest"})


def _is_sentinel_constant(node) -> bool:
    if not isinstance(node, ast.Constant):
        return False
    v = node.value
    return v is None or isinstance(v, bool) or v == 0 or v == "" or v == b""


def _is_strong_operand(node) -> bool:
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in _DIGEST_METHODS):
        return True
    if isinstance(node, ast.Name):
        tok = node.id
    elif isinstance(node, ast.Attribute):
        tok = node.attr
    else:
        return False
    if _METADATA_SUFFIX_RX.search(tok):
        return False
    return _STRONG_RX.search(tok) is not None


def _timing_unsafe_node_match(node: ast.AST) -> Optional[str]:
    if not isinstance(node, ast.Compare) or not node.ops:
        return None
    operands = [node.left] + list(node.comparators)
    for left, op, right in zip(operands, node.ops, operands[1:]):
        if not isinstance(op, (ast.Eq, ast.NotEq)):
            continue
        if _is_sentinel_constant(left) or _is_sentinel_constant(right):
            continue
        if _is_strong_operand(left) or _is_strong_operand(right):
            return "timing-unsafe == of a secret/digest (use hmac.compare_digest)"
    return None


# --- ward.jwt_none_alg ---------------------------------------------------------------------------
def _is_none_alg(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.lower() == "none"


def _algorithms_whitelists_none(value) -> bool:
    if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return False
    return any(_is_none_alg(elt) for elt in value.elts)


def _jwt_none_node_match(node: ast.AST) -> Optional[str]:
    if jwt_decode_callee_chain(node) is None:
        return None
    for kw in node.keywords:
        if kw.arg == "algorithms" and _algorithms_whitelists_none(kw.value):
            return 'algorithms=["none"]'
    return None


# --- ward.jwt_signature_disabled ------------------------------------------------------------------
def _options_disables_signature(value) -> bool:
    if isinstance(value, ast.Dict):
        for k, v in zip(value.keys, value.values):
            if isinstance(k, ast.Constant) and k.value == "verify_signature" and is_false_const(v):
                return True
    if isinstance(value, ast.Call) and callee_chain(value) == "dict":
        for kw in value.keywords:
            if kw.arg == "verify_signature" and is_false_const(kw.value):
                return True
    return False


def _jwt_signature_node_match(node: ast.AST) -> Optional[str]:
    if jwt_decode_callee_chain(node) is None:
        return None
    for kw in node.keywords:
        if kw.arg == "verify" and is_false_const(kw.value):
            return "verify=False"
        if kw.arg == "options" and _options_disables_signature(kw.value):
            return 'options={"verify_signature": False}'
    return None


# --- ward.cert_verify_disabled ---------------------------------------------------------------------
_FALSE_KEYWORDS = frozenset({"verify", "check_hostname"})
_UNVERIFIED_ATTRS = frozenset({"_create_unverified_context"})
_TLS_CALLEE_RX = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:requests|httpx|aiohttp|urllib3|pycurl|session|http[_.]?client"
    r"|ssl|sslcontext|create_default_context|create_urllib3_context|wrap_socket)(?:$|[^a-z0-9])"
)


def _cert_verify_node_match(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Attribute) and node.attr in _UNVERIFIED_ATTRS:
        return f".{node.attr}"
    targets, value = assignment_parts(node)
    if is_false_const(value):
        for tgt in targets:
            if isinstance(tgt, ast.Attribute) and tgt.attr == "check_hostname":
                return "check_hostname=False (assigned)"
    if isinstance(node, ast.Call) and _TLS_CALLEE_RX.search(callee_chain(node)):
        for kw in node.keywords:
            if kw.arg in _FALSE_KEYWORDS and is_false_const(kw.value):
                return f"{kw.arg}=False"
    return None


# --- ward.cert_reqs_none --------------------------------------------------------------------------
def _cert_reqs_none_node_match(node: ast.AST) -> Optional[str]:
    if not isinstance(node, ast.Call) or not _TLS_CALLEE_RX.search(callee_chain(node)):
        return None
    for kw in node.keywords:
        if kw.arg == "cert_reqs" and is_cert_none(kw.value):
            return "cert_reqs=CERT_NONE"
    return None


# --- ward.cert_none_mode --------------------------------------------------------------------------
def _cert_none_node_match(node: ast.AST) -> Optional[str]:
    targets, value = assignment_parts(node)
    if not is_cert_none(value):
        return None
    for tgt in targets:
        if isinstance(tgt, ast.Attribute) and tgt.attr == "verify_mode":
            return "verify_mode = CERT_NONE"
    return None


# --- ward.paramiko_host_key_weakened ----------------------------------------------------------------
_SET_POLICY_METHOD = "set_missing_host_key_policy"
_WEAK_POLICIES = frozenset({"AutoAddPolicy", "WarningPolicy"})


def _policy_ref_name(node) -> Optional[str]:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _host_key_policy_node_match(node: ast.AST) -> Optional[str]:
    if not isinstance(node, ast.Call):
        return None
    if callee_chain(node).split(".")[-1] != _SET_POLICY_METHOD:
        return None
    policy = node.args[0] if node.args else next(
        (kw.value for kw in node.keywords if kw.arg == "policy"), None
    )
    if policy is None:
        return None
    policy_name = _policy_ref_name(policy)
    if policy_name in _WEAK_POLICIES:
        return f"set_missing_host_key_policy({policy_name})"
    return None


# ================================================================================================
# The checks that don't scan introduced Python AST — stay their own functions, same honest
# reason the AST-scaffolded 7 above get tabled and these don't: forcing a path-lexical test and an
# outbound-JSON-payload scan into the AST scaffold would fake a shared shape neither one has.
# ================================================================================================

# --- ward.forbidden_location (ported by SHAPE from Makoto's forbiddenLocation.py; the Makoto-own
# control-plane/state-home self-guard segments are dropped here — Ward has no state directory of
# its own and this is no longer Makoto's file, so guarding Makoto's paths would be a stale claim,
# not a real protection. The host harness's own plan-file sanction is kept: it is the one
# out-of-cwd location the harness itself instructs an agent to write to, real regardless of which
# tool is asking.) -------------------------------------------------------------------------------
_SYSTEM_ROOT_DIRS = frozenset({"etc", "boot", "sys", "proc", "dev"})
_PROTECTED_DIR_SEGMENTS = frozenset({
    ".ssh", ".gnupg", ".aws", ".config", ".kube", ".docker",
})
_SHELL_RC_BASENAMES = frozenset({
    ".bashrc", ".bash_profile", ".bash_login", ".profile",
    ".zshrc", ".zprofile", ".zshenv", ".zlogin",
    ".cshrc", ".tcshrc", ".kshrc", ".login",
})
_CREDENTIAL_BASENAMES = frozenset({
    ".netrc", ".pgpass", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials", ".npmrc", ".pypirc", ".git-credentials", "authorized_keys",
})
_WRITE_NAMES = frozenset({"Write", "MultiEdit"})
_EDIT_NAMES = frozenset({"Edit", "NotebookEdit"})
_LOCATION_KEYS = ("file_path", "notebook_path")
_WINDOWS_DRIVE_RELATIVE_RX = re.compile(r"^[A-Za-z]:(?:$|[^/\\])")


def _is_ambiguous_security_keyword_fragment(tree: ast.AST) -> bool:
    """True for an Edit replacement that is a dangerous keyword without its call context.

    ``verify=False`` is valid *module* syntax (an assignment), but an Edit replacement has no
    surrounding source for Ward to establish whether it is that benign assignment or a keyword in
    ``requests.get(..., verify=False)``.  The latter is confirmed dangerous, so treating this
    ambiguous, security-sensitive fragment as clean is an input-evaluation failure, not a pass.
    """
    if not isinstance(tree, ast.Module) or len(tree.body) != 1:
        return False
    statement = tree.body[0]
    targets, value = assignment_parts(statement)
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        return False
    keyword = targets[0].id
    if keyword in {"verify", "verify_signature"}:
        return is_false_const(value)
    if keyword == "cert_reqs":
        return is_cert_none(value)
    return False


def _cannot_evaluate(event: dict[str, Any]) -> Optional[str]:
    """Return why a mutation event lacks input Ward must inspect, else ``None``.

    A missing path used to make both the lexical path check and every AST check silently skip a
    Write/Edit.  That is not a clean result: Ward has lost the information needed to decide
    whether the pending mutation is safe.  Keep this preflight outside ``CHECKS`` so the eleven
    substantive predicates remain the advertised table; this is the dispatcher-facing failure
    direction for an event those predicates cannot be evaluated against.
    """
    if event.get("hook_event_name") != "PreToolUse":
        return None
    name = event.get("tool_name")
    if name not in _WRITE_NAMES and name not in _EDIT_NAMES:
        return None
    ti = event.get("tool_input")
    if not isinstance(ti, dict):
        return "required tool_input object is missing"
    path_key = "notebook_path" if name == "NotebookEdit" else "file_path"
    path = ti.get(path_key)
    if not isinstance(path, str) or not path:
        return f"required {path_key} is missing"
    if name == "Write" and (not isinstance(ti.get("content"), str) or not ti["content"]):
        return "required Write content is missing or empty"
    if name == "Edit" and (not isinstance(ti.get("new_string"), str) or not ti["new_string"]):
        return "required Edit new_string is missing or empty"
    if name == "MultiEdit":
        edits = ti.get("edits")
        if not isinstance(edits, list) or not edits or any(
            not isinstance(edit, dict) or not isinstance(edit.get("new_string"), str)
            or not edit["new_string"]
            for edit in edits
        ):
            return "required MultiEdit edits/new_string input is missing or empty"
    if _PY_FILE_RX.search(path):
        for content in scan_target_contents(ti):
            tree, _ = _parse_introduced(content)
            if tree is None:
                return "introduced Python fragment cannot be parsed independently"
            if name in _EDIT_NAMES and _is_ambiguous_security_keyword_fragment(tree):
                return "introduced Python fragment contains a security-sensitive keyword without its call context"
    return None


def _lexical_resolve(path: str) -> PurePosixPath:
    """Normalize hook paths to a portable POSIX form, then collapse ``.``/``..`` lexically.

    Claude Code supplies backslash-separated absolute paths on Windows even when the hook runs
    under Git Bash. Absolute drive paths and UNC paths are mapped below a synthetic POSIX root so
    the containment checks have one representation on every platform. A UNC host/share pair is an
    anchor: ``..`` may remove only segments *below* that share. Windows paths are case-folded
    because their normal filesystem semantics are case-insensitive. No disk access is performed.
    """
    normalized = path.replace("\\", "/")
    drive_match = re.match(r"^([A-Za-z]):/", normalized)
    if drive_match:
        normalized = f"/{drive_match.group(1).lower()}:{normalized[2:]}".casefold()
    elif normalized.startswith("//"):
        unc_parts = [part.casefold() for part in normalized.split("/") if part]
        if len(unc_parts) >= 2:
            # ``\\host\\share`` is a volume root.  In particular, normalizing
            # ``\\host\\other\\..\\share`` must remain under the ``other`` share rather than
            # turning into the distinct ``share`` volume.
            resolved = ["unc", unc_parts[0], unc_parts[1]]
            for part in unc_parts[2:]:
                if part in (".", ""):
                    continue
                if part == "..":
                    if len(resolved) > 3:
                        resolved.pop()
                    continue
                resolved.append(part)
            return PurePosixPath("/", *resolved)
        normalized = "/unc/" + normalized.lstrip("/").casefold()
    p = PurePosixPath(normalized)
    anchor = p.anchor
    is_absolute = bool(anchor)
    resolved: list[str] = []
    parts = p.parts[1:] if is_absolute else p.parts
    for part in parts:
        if part in (".", ""):
            continue
        if part == "..":
            if resolved and resolved[-1] != "..":
                resolved.pop()
            elif not is_absolute:
                resolved.append("..")
            continue
        resolved.append(part)
    if is_absolute:
        return PurePosixPath(anchor, *resolved)
    if not resolved:
        return PurePosixPath(".")
    return PurePosixPath(*resolved)


def _resolves_outside_cwd(file_path: str, cwd: str) -> Optional[bool]:
    # ``C:relative.txt`` means "relative to C:'s current directory", a different and hidden
    # base from the event cwd.  It cannot be safely compared to any cwd lexically, even another
    # C: path, so refuse it rather than treating the colon as an ordinary in-cwd filename.
    if _WINDOWS_DRIVE_RELATIVE_RX.match(file_path):
        return True
    fp = _lexical_resolve(file_path)
    if not fp.is_absolute():
        if not cwd:
            return None
        base = _lexical_resolve(cwd)
        if not base.is_absolute():
            return None
        target = _lexical_resolve(str(base / fp))
        root = base
    else:
        target = _lexical_resolve(file_path)
        if not cwd:
            return None
        root = _lexical_resolve(cwd)
    if str(target) == str(root):
        return False
    root_parts, target_parts = root.parts, target.parts
    if len(target_parts) < len(root_parts):
        return True
    if target_parts[: len(root_parts)] == root_parts:
        return False
    return True


def _is_under(root: PurePosixPath, target: PurePosixPath) -> bool:
    if not root.is_absolute():
        return False
    root_parts, target_parts = root.parts, target.parts
    if len(target_parts) < len(root_parts):
        return False
    return target_parts[: len(root_parts)] == root_parts


def _under_harness_plans(target: PurePosixPath) -> bool:
    """True iff `target` lies at/under the host harness's own designated plan-artifact home,
    `<config-dir>/plans` — the one out-of-cwd location the harness itself instructs an agent to
    write to. Claude relocates its default `~/.claude` root when `CLAUDE_CONFIG_DIR` is set."""
    from pathlib import Path
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    config_root = configured or str(PurePosixPath(Path.home().as_posix()) / ".claude")
    return _is_under(_lexical_resolve(str(PurePosixPath(config_root) / "plans")), target)


def _location_reason(name: str, file_path: str, cwd: str) -> Optional[str]:
    fp = _lexical_resolve(file_path)
    if fp.is_absolute():
        target = fp
    elif cwd and _lexical_resolve(cwd).is_absolute():
        target = _lexical_resolve(str(_lexical_resolve(cwd) / fp))
    else:
        target = fp

    segments = target.parts
    basename = target.name

    if (target.is_absolute() and len(segments) > 1
            and segments[1].lower() in _SYSTEM_ROOT_DIRS):
        return f"protected-directory: target lies under system root {segments[1]!r}"

    for seg in segments:
        if seg.lower() in _PROTECTED_DIR_SEGMENTS:
            return f"protected-directory: target lies under protected segment {seg!r}"

    if basename in _SHELL_RC_BASENAMES:
        return f"shell-rc: target basename {basename!r} is a shell startup file"

    if basename.lower() in _CREDENTIAL_BASENAMES:
        return f"credential-basename: {name} to credential file {basename!r}"

    if _under_harness_plans(target):
        return None  # harness-designated plan home — sanctioned, not an escape

    outside = _resolves_outside_cwd(file_path, cwd)
    if outside is True:
        return "path-policy: target lexically normalizes outside the working directory"

    return None


def _location_arg(tool_input: dict) -> Optional[str]:
    for key in _LOCATION_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def forbidden_location(event: dict) -> Optional[str]:
    """Write/Edit/MultiEdit/NotebookEdit path text lexically falls outside cwd or names a
    protected system/credential dir, shell-rc file, or credential basename. Pure PurePosixPath
    lexical policy test — no disk access, no content read, and no claim about the later writer's
    filesystem resolution. Ported by SHAPE from Makoto's forbiddenLocation.py."""
    if event.get("hook_event_name") != "PreToolUse":
        return None
    name = event.get("tool_name", "")
    if name not in _WRITE_NAMES and name not in _EDIT_NAMES:
        return None
    ti = event.get("tool_input") or {}
    if not isinstance(ti, dict):
        return None
    file_path = _location_arg(ti)
    if file_path is None:
        return None
    cwd = event.get("cwd", "")
    if not isinstance(cwd, str):
        cwd = ""
    return _location_reason(name, file_path, cwd)


# --- ward.outbound_secret_pattern (ported by SHAPE from Detent's outbound_deny_secret_pattern) --
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("GitHub personal access token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
)


def _is_world_tool(name: str) -> bool:
    """The →WORLD tool class, as an exact predicate instead of an enumerated row list. Every
    mcp__* tool is WORLD (MCP servers are WORLD even if local); WebFetch/WebSearch reach the
    network by definition."""
    return name.startswith("mcp__") or name in ("WebFetch", "WebSearch")


def outbound_secret_pattern(event: dict) -> Optional[str]:
    """Deny publishing a payload matching an exact secret grammar through ANY →WORLD-class tool —
    membership decided by `_is_world_tool`'s predicate, never an enumerated row list a new MCP
    server could silently escape. Names the pattern kind only, never the match. Fails open on a
    payload matching no grammar — a tripwire, not a scanner with opinions."""
    if event.get("hook_event_name") != "PreToolUse":
        return None
    name = event.get("tool_name")
    if not isinstance(name, str) or not _is_world_tool(name):
        return None
    ti = event.get("tool_input")
    blob = json.dumps(ti if isinstance(ti, dict) else {})
    for kind, pattern in _SECRET_PATTERNS:
        if pattern.search(blob):
            return f"outbound payload matches the {kind} pattern"
    return None


# --- ward.self_mute_guard -----------------------------------------------------------------------
# Ported by shape from Makoto's makoto/checks/selfMuteGuard.py.  Makoto protects its particular
# settings hook; Ward translates the same removed-vs-introduced predicate to the pending source
# mutation itself, without reading the target or consulting history.
_CHECK_WORD = r"(?:audit|verif(?:y|ier|ication)?|integrit(?:y|ies)|attest|checksum|signature|tamper|provenance)"
_CHECK_SYMBOL_RX = re.compile(
    rf"(?i)\b(?:def\s+)?([A-Za-z_]\w*{_CHECK_WORD}\w*|{_CHECK_WORD}[A-Za-z_]\w*)\s*(?=\()"
)
_DISABLED_CHECK_RX = re.compile(
    rf"(?im)^\s*[\"']?\w*{_CHECK_WORD}\w*[\"']?\s*[:=]\s*(?:false|0|none|off)\b"
)


def _removed_contents(tool_input: dict) -> tuple[str, ...]:
    old = tool_input.get("old_string")
    if isinstance(old, str) and old:
        return (old,)
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        return tuple(edit.get("old_string", "") for edit in edits
                     if isinstance(edit, dict) and isinstance(edit.get("old_string"), str))
    return ()


def self_mute_guard(event: dict) -> Optional[str]:
    """Deny a mutation that explicitly disables a verifier or removes its callable shape."""
    if event.get("hook_event_name") != "PreToolUse" or event.get("tool_name") not in {
        "Write", "Edit", "MultiEdit",
    }:
        return None
    ti = event.get("tool_input")
    if not isinstance(ti, dict):
        return None
    path = ti.get("file_path", "")
    if not isinstance(path, str) or not re.search(
        r"(?i)\.(?:py|toml|ya?ml|json|ini|cfg|conf|sh|bash|zsh)$", path
    ):
        return None
    introduced_parts = scan_target_contents(ti)
    introduced = "\n".join(introduced_parts)
    disabled = _DISABLED_CHECK_RX.search(introduced)
    if disabled:
        return f"introduces an explicit verifier/check disable ({disabled.group(0).strip()!r})"

    removed_symbols = {
        match.group(1).casefold()
        for content in _removed_contents(ti)
        for match in _CHECK_SYMBOL_RX.finditer(content)
    }
    introduced_symbols = {
        match.group(1).casefold()
        for content in introduced_parts
        for match in _CHECK_SYMBOL_RX.finditer(content)
    }
    gone = sorted(removed_symbols - introduced_symbols)
    if gone:
        return f"removes verifier/check callable {gone[0]!r} from the replacement"
    return None


# --- ward.integrity_suppression_flag -------------------------------------------------------------
# Ported by shape from Makoto's makoto/checks/integritySuppressionFlag.py.  Ward includes the
# env-gate spelling requested by its action-only threat model; it still scans introduced text only.
_SUPPRESSION_SUFFIX = r"(?:skip|bypass|inapplicable|disable|suppress)"
_INTEGRITY_FLAG_RX = re.compile(
    rf"(?im)^\s*[\"']?\w*{_CHECK_WORD}\w*[_-]{_SUPPRESSION_SUFFIX}[\"']?\s*[:=]\s*(?:true|1|yes|on)\b"
)
_INTEGRITY_ENV_RX = re.compile(
    rf"(?ix)(?:os\.(?:getenv|environ\.get)\s*\(\s*[\"']|os\.environ\s*\[\s*[\"']|"
    rf"getenv\s*\(\s*[\"']|\$\{{?)(?=[A-Z0-9_]*(?:{_CHECK_WORD}))"
    rf"(?=[A-Z0-9_]*(?:{_SUPPRESSION_SUFFIX}))[A-Z][A-Z0-9_]*"
)
_MUTATION_TEXT_SUFFIX_RX = re.compile(r"(?i)\.(?:py|toml|ya?ml|json|ini|cfg|conf|sh|bash|zsh)$")


def integrity_suppression_flag(event: dict) -> Optional[str]:
    """Deny introducing an integrity-named suppression flag or environment-variable gate."""
    if event.get("hook_event_name") != "PreToolUse" or event.get("tool_name") not in {
        "Write", "Edit", "MultiEdit",
    }:
        return None
    ti = event.get("tool_input")
    if not isinstance(ti, dict):
        return None
    path = ti.get("file_path", "")
    if not isinstance(path, str) or not _MUTATION_TEXT_SUFFIX_RX.search(path):
        return None
    for content in scan_target_contents(ti):
        flag = _INTEGRITY_FLAG_RX.search(content)
        if flag:
            return f"introduces an integrity suppression flag ({flag.group(0).strip()!r})"
        env_gate = _INTEGRITY_ENV_RX.search(content)
        if env_gate:
            return f"introduces an environment-variable gate that can silence verification ({env_gate.group(0)!r})"
    return None


# ================================================================================================
# The table — 11 rows, zero new dispatch code for a future check (matches Detent's own stated
# design promise: "one row, zero new code").
# ================================================================================================

CHECKS: list[tuple[str, str, str]] = [
    ("ward.forbidden_location",
     "Write/Edit path text lexically falls outside cwd or names a protected location",
     "Choose path text that stays within the working-directory policy and avoids protected "
     "system/credential locations. The file-tool host must enforce containment at open time."),
    ("ward.timing_unsafe_compare",
     "timing-unsafe ==/!= comparison of a secret/HMAC/digest (use hmac.compare_digest)",
     "Don't compare a secret/HMAC/digest with `==`/`!=` — a byte-by-byte short-circuiting compare "
     "leaks match-length timing (CWE-208). Use `hmac.compare_digest(a, b)`. If legitimate, "
     "annotate the line `ward-allow: <reason>`."),
    ("ward.jwt_none_alg",
     "JWT decode allow-list whitelists the unsigned 'none' algorithm (alg-confusion bypass)",
     "Don't put 'none' in a jwt/jose `decode(..., algorithms=[...])` allow-list (RFC 8725 "
     "sections 2.1 and 3.1; CWE-347). List only real signing algorithms. If legitimate, annotate the line "
     "`ward-allow: <reason>`."),
    ("ward.jwt_signature_disabled",
     "JWT signature verification disabled (jwt.decode verify=False / verify_signature=False)",
     "Don't disable JWT signature verification — it makes decode accept ANY token, including a "
     "forged one. Verify the signature with the issuer's key/algorithm. If legitimate, annotate "
     "the line `ward-allow: <reason>`."),
    ("ward.cert_verify_disabled",
     "TLS/certificate verification disabled (verify=False / unverified SSL context)",
     "Don't disable TLS verification — the peer-identity check becomes a no-op while the call "
     "still 'succeeds'. Use proper certs (or pin a CA). If legitimate, annotate the line "
     "`ward-allow: <reason>`."),
    ("ward.cert_reqs_none",
     "cert_reqs=ssl.CERT_NONE kwarg disables peer-certificate verification at the call site",
     "Don't pass `cert_reqs=ssl.CERT_NONE` to a TLS call (CWE-295). Use `cert_reqs=ssl.CERT_REQUIRED` "
     "with a CA. If legitimate, annotate the line `ward-allow: <reason>`."),
    ("ward.cert_none_mode",
     "certificate verification disabled (SSLContext verify_mode = CERT_NONE)",
     "Don't set an SSLContext's `verify_mode = ssl.CERT_NONE` — the context accepts ANY peer "
     "certificate. Use CERT_REQUIRED with a proper trust store. If legitimate, annotate the line "
     "`ward-allow: <reason>`."),
    ("ward.paramiko_host_key_weakened",
     "paramiko SSH host-key verification weakened to AutoAddPolicy/WarningPolicy (auto-trust unknown keys)",
     "Don't pass `AutoAddPolicy` or `WarningPolicy` to paramiko's `set_missing_host_key_policy(...)` "
     "(Bandit B507; CWE-295). Use the default `RejectPolicy`. If legitimate, annotate the line "
     "`ward-allow: <reason>`."),
    ("ward.outbound_secret_pattern",
     "outbound payload matches a known secret/credential grammar",
     "Redact the credential (and rotate it if real), then retry."),
    ("ward.self_mute_guard",
     "pending edit removes or explicitly disables a verifier/check",
     "Keep the verifier/check active in this change; any operator-approved removal must happen "
     "outside the guarded tool call."),
    ("ward.integrity_suppression_flag",
     "introduced flag or environment gate suppresses an integrity/audit/verification path",
     "Remove the suppression flag or environment gate and keep the integrity path unconditional."),
]

_FN_BY_ID: dict[str, Callable[[dict], Optional[str]]] = {
    "ward.forbidden_location": forbidden_location,
    "ward.timing_unsafe_compare": _ast_introduced_check(_timing_unsafe_node_match),
    "ward.jwt_none_alg": _ast_introduced_check(_jwt_none_node_match),
    "ward.jwt_signature_disabled": _ast_introduced_check(_jwt_signature_node_match),
    "ward.cert_verify_disabled": _ast_introduced_check(_cert_verify_node_match),
    "ward.cert_reqs_none": _ast_introduced_check(_cert_reqs_none_node_match),
    "ward.cert_none_mode": _ast_introduced_check(_cert_none_node_match),
    "ward.paramiko_host_key_weakened": _ast_introduced_check(_host_key_policy_node_match),
    "ward.outbound_secret_pattern": outbound_secret_pattern,
    "ward.self_mute_guard": self_mute_guard,
    "ward.integrity_suppression_flag": integrity_suppression_flag,
}


def evaluate(event: dict[str, Any]) -> Optional[tuple[str, str]]:
    """Run every check in table order; return (check_id, message) for the first that fires, else
    None. `message` is the description + retry hint + the check's own specific reason."""
    cannot_evaluate = _cannot_evaluate(event)
    if cannot_evaluate:
        return (
            "ward.cannot_evaluate",
            "Denied (Ward cannot evaluate this pending mutation): "
            f"{cannot_evaluate}. Retry with complete tool input; Ward fails closed when it "
            "cannot inspect an action.",
        )
    for check_id, description, retry_hint in CHECKS:
        reason = _FN_BY_ID[check_id](event)
        if reason:
            return check_id, f"Denied ({description}): {reason}. {retry_hint}"
    return None

"""ward.wire -- the byte boundary: raw hook stdin -> a str Ward's checks can parse.

PORTED BY SHAPE from Makoto's `makoto/core/wire.py`, not imported. Ward takes no cross-repo
dependency (see ward.checks' module docstring: copy, never a dependency), and the copy is
deliberate -- these three plugins ship and version independently, and a shared runtime import
would make one plugin's install failure the whole bench's outage.

WHY THIS EXISTS, IN WARD'S OWN TERMS
`read_event` opened with `sys.stdin.read()`. A hook subprocess inherits no LANG, so CPython enables
UTF-8 mode and gives stdin the `surrogateescape` error handler: a host byte that is not valid UTF-8
enters as a lone surrogate instead of raising or being replaced. That str parses as JSON and
reaches `_parse_introduced`, where `ast.parse` refuses it -- and `_cannot_evaluate` then returns
"introduced Python fragment cannot be parsed independently", so Ward HARD-DENIES the call.

Measured on this exact input: a Write of a perfectly valid Python file whose only sin was one
CP1252 byte in a comment was denied, and the reason named a parse failure that was never the
file's. The failure direction was right -- Ward fails closed and should -- but the FACT was wrong,
and a deny whose stated reason is false cannot be acted on: the agent rewrites code that was never
the problem, the byte survives every rewrite, and the loop does not heal.

The same byte reaches Makoto and Gyroscope through the same door and gets two other verdicts
(fail-open with the check skipped; silent per-clause abstention). Three plugins, one bad byte,
three different answers, none of them about the pending action. Hence a boundary in each, so no
check anywhere is ever handed a lone surrogate to be confused by.

ONE GUARANTEE: no surrogate code point survives this module. It is not a sanitizer for hostile
input and makes no security claim -- `ward.checks` still decides everything about the action.
"""
from __future__ import annotations

import re
import sys
from typing import Any

REPLACEMENT = "�"

# The whole surrogate range. The byte decode below routes its own surrogates back through here;
# this regex also closes the other door -- a well-formed UTF-8 payload whose JSON TEXT carries an unpaired
# `\ud89d` escape, which `json.loads` faithfully turns into a real lone surrogate.
_SURROGATE_RX = re.compile("[\ud800-\udfff]")


def scrub_text(text: str) -> tuple[str, int]:
    """Return (text with every surrogate code point replaced, number replaced)."""
    if not _SURROGATE_RX.search(text):
        return text, 0
    # `subn` returns (result, count) from ONE pass. The earlier form ran `sub` and then
    # `findall`, scanning the damaged text twice and building a throwaway list of every
    # match to get a number `subn` already had. Measured 2.0x on the repair path.
    return _SURROGATE_RX.subn(REPLACEMENT, text)


def scrub(value: Any) -> tuple[Any, int]:
    """Recursively scrub every str inside a parsed JSON value; return (value, total replaced).

    Keys as well as values: a surrogate in a key reaches the same encoder, and an unserializable
    key fails a whole row rather than one field. Containers are rebuilt only when something below
    them changed, so a clean event comes back as the objects it went in as.
    """
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        out, total, next_suffix = {}, 0, {}
        for k, v in value.items():
            if isinstance(k, str):
                k, n = scrub_text(k)
                total += n
                if n:
                    # Scrubbing is NOT injective on keys: every surrogate becomes the same U+FFFD,
                    # so two genuinely different damaged keys collapse onto one name and the plain
                    # assignment below dropped the earlier one's VALUE on the floor without a word.
                    # `wire.scrub({"\ud800": 1, "\ud801": 2})` returned `({'\ufffd': 2}, 2)` -- a
                    # count of 2 repairs next to a dict that had lost a field. This module's one
                    # promise is that repair is on the record; silently deleting a field is the
                    # opposite of that, and the field could be `tool_input`. The suffix keeps both
                    # values reachable and keeps the collision visible in the persisted row.
                    # Tested against `value` as well as `out` so a CLEAN key later in the dict
                    # keeps its own name rather than being overwritten by a repaired one.
                    #
                    # `next_suffix` resumes where this base's last search stopped instead of
                    # restarting at 2. Every suffix below that point was already rejected as taken,
                    # and neither `out` nor `value` ever gives a name back, so the names handed out
                    # are exactly the ones the rescan produced, in a constant number of probes
                    # per key rather than a walk from 2. The rescan was QUADRATIC in the number of
                    # keys collapsing onto one name, and that number is attacker-influenced: 4096
                    # `\uD8xx`-escaped keys in one `tool_input` measured 18s inside a PreToolUse
                    # hook (0.06s here), and a host timeout on a hook is no decision at all.
                    base = k
                    suffix = next_suffix.get(base, 2)
                    while k in out or k in value:
                        k = f"{base}~{suffix}"
                        suffix += 1
                    next_suffix[base] = suffix
            v, n = scrub(v)
            total += n
            out[k] = v
        return (out, total) if total else (value, 0)
    if isinstance(value, list):
        items, total = [], 0
        for item in value:
            item, n = scrub(item)
            total += n
            items.append(item)
        return (items, total) if total else (value, 0)
    return value, 0


def read_stdin() -> tuple[str, int]:
    """Read the hook envelope as BYTES and decode it to a surrogate-free str; (text, repaired).

    Reading `.buffer` is the load-bearing part: it takes the decode away from whatever error
    handler the ambient locale installed and puts it under this module's own control, where every
    surrogate it produces is scrubbed before the value is returned.
    """
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is not None:
        try:
            data = buffer.read()
        except (AttributeError, ValueError, OSError):
            pass
        else:
            return _decode_counting(data)
    return scrub_text(sys.stdin.read() or "")


def _decode_counting(data: bytes) -> tuple[str, int]:
    """Decode `data` as UTF-8, returning (text, number of undecodable BYTES repaired).

    Strict first, on purpose: a clean payload reports zero repairs by construction, so the count can
    never be inflated by a U+FFFD the host legitimately sent. A number that cries wolf gets ignored,
    and takes the next real one with it.
    """
    try:
        return scrub_text(data.decode("utf-8"))
    except UnicodeDecodeError:
        # `surrogateescape`, then scrub -- NOT `errors="replace"`.
        #
        # `replace` emits ONE U+FFFD per malformed RUN, so a truncated three-byte sequence like
        # b"\xe2\x82" (two undecodable bytes) reported 1, and the field is called "bytes repaired".
        # An observability number whose name does not match its arithmetic is the kind of thing that
        # gets trusted right up until someone reconciles two counts and cannot.
        #
        # `surrogateescape` maps each undecodable BYTE to exactly one lone surrogate, so counting the
        # surrogates counts bytes -- which is what the field says. Scrubbing them immediately is what
        # keeps the module's one guarantee: no surrogate leaves here. It also retires the
        # `data.count(b"\xef\xbf\xbd")` correction entirely, since surrogateescape never touches a
        # U+FFFD the host legitimately sent.
        return scrub_text(data.decode("utf-8", errors="surrogateescape"))

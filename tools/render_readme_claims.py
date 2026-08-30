#!/usr/bin/env python3
"""Render README measurements from their repository-owned sources."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

from measure import derailment_rules, check_count, contiguous_count, corpus_counts, suite_count


ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"


def replay_result() -> tuple[int, int]:
    proc = subprocess.run([sys.executable, "eval/replay.py"], cwd=ROOT,
                          text=True, capture_output=True)
    match = re.search(r"REPLAY sessions=(\d+) passed=(\d+) failed=(\d+)", proc.stdout)
    if proc.returncode or not match:
        raise RuntimeError("eval/replay.py did not produce a passing REPLAY summary")
    sessions, passed, failed = map(int, match.groups())
    if failed:
        raise RuntimeError("eval/replay.py reported failed sessions")
    return passed, sessions


def generated() -> dict[str, str]:
    rows = check_count()
    contiguous = contiguous_count()
    tests = suite_count()
    sessions, derailments = corpus_counts()
    passed, executed = replay_result()
    if sessions != executed:
        raise RuntimeError("corpus count and replay session count disagree")
    return {
        "quickstart-checks":
            f"Ward is a Claude Code `PreToolUse` plugin: an ordered {rows}-row table of exact denials over the\n"
            "pending tool call. A match denies with a citation and a retry hint; anything else is a silent\n"
            "`{}`. No state, no history, and nothing configurable about what it denies.",
        "checks-heading":
            f"The ordered `CHECKS` table in [plugin/ward/checks.py](plugin/ward/checks.py) contains these {rows} rows. The first\n"
            "matching row wins.",
        "contiguous-checks":
            f"The {contiguous} rows from `ward.timing_unsafe_compare` through\n"
            "`ward.paramiko_host_key_weakened` parse only newly introduced Python in a `.py` mutation. The other\n"
            f"{rows - contiguous} use path text, serialized outbound payloads, or introduced-versus-removed mutation text.",
        "dispatch-image":
            "<picture>\n"
            '  <source media="(prefers-color-scheme: dark)" srcset="docs/img/dispatch-flow-dark.png">\n'
            f'  <img src="docs/img/dispatch-flow-light.png" alt="Pending tool call through Ward\'s single entrypoint and {rows}-row denial table">\n'
            "</picture>",
        "preflight-checks":
            f"Before the {rows} rows, a separate `ward.cannot_evaluate` preflight denies a file mutation whose\n"
            "required path or introduced text is missing, empty, independently unparseable Python, or an\n"
            "ambiguous detached security keyword. Malformed input or a shim that cannot start also produces a\n"
            "fail-closed denial, as does an internal dispatcher error while a `PreToolUse` check is due to run.",
        "suite-output":
            "$ python3 -m unittest discover -s tests\n"
            "...\n"
            f"Ran {tests} tests in <elapsed>s\n\n"
            "OK",
        "replay-summary":
            "Beyond the unit suite, `python3 eval/replay.py` replays recorded sessions through the real\n"
            f"dispatcher: {derailments} derailments — one for every row of the table — each denied at the\n"
            "event where the session went wrong, and by the row that names it:\n\n"
            + "".join(f"  - `ward.{rule}`\n" for rule in derailment_rules())
            + f"\nand a benign control that stays silent — {passed}/{executed}, standard library only.",
        "suite-count":
            f"The shipped suite contains {tests} tests. Keep new predicates narrow, add both firing and clean cases,\n"
            "and exercise the shell entrypoint when changing hook wiring.",
    }


def render(text: str) -> str:
    for name, body in generated().items():
        pattern = re.compile(
            rf"(<!-- BEGIN GENERATED {re.escape(name)} -->)\n.*?"
            rf"(<!-- END GENERATED {re.escape(name)} -->)",
            re.DOTALL,
        )
        text, replacements = pattern.subn(rf"\g<1>\n{body}\n\g<2>", text)
        if replacements != 1:
            raise RuntimeError(f"expected exactly one generated block named {name}, found {replacements}")
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    current = README.read_text(encoding="utf-8")
    expected = render(current)
    if args.check:
        if current != expected:
            print("README.md generated measurements are stale; run tools/render_readme_claims.py",
                  file=sys.stderr)
            return 1
        print("README.md generated measurements are current")
        return 0
    README.write_text(expected, encoding="utf-8")
    print("rendered README.md measurements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

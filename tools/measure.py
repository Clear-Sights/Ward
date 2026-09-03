#!/usr/bin/env python3
"""Print repository-owned measurements used by README evidence."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugin"


def child_env() -> dict[str, str]:
    """The environment for every subprocess these tools measure through.

    `checks()` below pins `plugin/` onto `sys.path` for its own in-process reads, but the
    subprocess measurements did not pin anything: they inherited the caller's environment, so
    `import ward` inside the child resolved to whatever `ward` that environment already had --
    an installed sibling package, a stale editable install, an unrelated checkout. The number
    that came back was then rendered into README.md as this repository's evidence while
    describing other bytes, and with no `ward` importable at all the same omission surfaced as
    the bare `RuntimeError: unit suite did not produce a passing test count`, which names the
    symptom and not the cause. The half-pin is the bug: one half of this file graded the
    repository and the other half graded the environment.

    `plugin/` is PREPENDED, not appended, so it wins over an inherited entry rather than only
    filling in for an absent one -- an appended path would still let a sibling `ward` grade.
    """
    env = dict(os.environ)
    # A measurement spawns the suite, and the suite contains cells that call a measurement. The
    # marker makes that nesting terminate at depth one: a spawned child sees it and skips those
    # cells instead of spawning again. It bounds recursion only -- it never relaxes a check, and
    # the cells it stands down still run in full in the ordinary top-level suite, which is where
    # they are graded.
    env["WARD_MEASUREMENT_CHILD"] = "1"
    inherited = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{PLUGIN}{os.pathsep}{inherited}" if inherited else str(PLUGIN)
    return env


def checks() -> list[tuple[str, str, str]]:
    sys.path.insert(0, str(PLUGIN))
    from ward.checks import CHECKS
    return CHECKS


def check_count() -> int:
    return len(checks())


# The rows built on the shared AST-introduced scaffold, named as a SET rather than as a span.
# `contiguous_count` subtracted two declared positions, so it reported the same number no matter
# what sat between them: a row inside the span that stopped using the scaffold, or was replaced
# by something unrelated, left the count untouched. The claim is about which checks share the
# scaffold, so the members are named and the count is len() of them.
AST_SCAFFOLD_ROWS = (
    "ward.timing_unsafe_compare",
    "ward.cert_verify_disabled",
    "ward.cert_none_mode",
    "ward.cert_reqs_none",
    "ward.jwt_none_alg",
    "ward.jwt_signature_disabled",
    "ward.paramiko_host_key_weakened",
)


def contiguous_count() -> int:
    names = [row[0] for row in checks()]
    missing = [row for row in AST_SCAFFOLD_ROWS if row not in names]
    if missing:
        raise RuntimeError(
            f"AST_SCAFFOLD_ROWS names rows the table no longer carries: {missing}")
    first = names.index(AST_SCAFFOLD_ROWS[0])
    last = names.index(AST_SCAFFOLD_ROWS[-1])
    span = names[first:last + 1]
    # Compared as SETS: the order of rows in the table is a first-match concern that other
    # checks own, and pinning it here would make this raise on a reordering that changes nothing
    # about which checks share the scaffold.
    if sorted(span) != sorted(AST_SCAFFOLD_ROWS):
        raise RuntimeError(
            f"the AST-scaffold rows are no longer exactly the span from "
            f"{AST_SCAFFOLD_ROWS[0]} to {AST_SCAFFOLD_ROWS[-1]}: the table has {span}. "
            f"Either a row moved into that range or one of these moved out; the README sentence "
            f"about a contiguous block of scaffold rows is what goes stale.")
    return len(AST_SCAFFOLD_ROWS)


def suite_count() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=ROOT, text=True, capture_output=True, env=child_env(),
    )
    output = proc.stdout + proc.stderr
    match = re.search(r"^Ran (\d+) tests? in ", output, re.MULTILINE)
    if proc.returncode or not match:
        raise RuntimeError("unit suite did not produce a passing test count")
    count = int(match.group(1))
    # ZERO IS NOT A COUNT. `unittest discover` prints "Ran 0 tests" and "OK" and exits 0 when it
    # finds nothing, so this accepted a suite that had stopped being discovered -- and the README
    # sentence it feeds says "the shipped suite contains N tests", which would then have been
    # rendered, committed, and read as evidence over a suite that ran none. The same defect the
    # workflows guard against; this is the third place it had to be closed.
    if count == 0:
        raise RuntimeError(
            "unit suite discovered 0 tests. `unittest discover` reports OK and exits 0 on an "
            "empty collection, so this is a suite that was not found, not a suite that passed.")
    return count


def corpus_counts() -> tuple[int, int]:
    paths = sorted((ROOT / "eval" / "corpus").glob("*.jsonl"))
    headers = [json.loads(path.read_text(encoding="utf-8").splitlines()[0]) for path in paths]
    derailments = sum(header.get("expect", "fires") != "none" for header in headers)
    return len(paths), derailments


def derailment_partition() -> tuple[int, list[str]]:
    """Split the corpus's derailing sessions into the table rows and everything else.

    README's replay summary read "12 derailments -- one for every row of the table" while
    `CHECKS` has eleven rows: the twelfth session derails on the `ward.cannot_evaluate`
    preflight, which is deliberately not a row. Numerator and denominator were gathered by
    different rules, so nothing checked that they agreed and the sentence went on claiming
    a ratio that had stopped holding. Both halves come from one pass over the corpus here.

    Raises when the tabled half is not exactly one session per row, naming the rows the
    corpus no longer covers -- which is the condition the summary asserts.

    `checks()` names carry the `ward.` prefix; `derailment_rules()` names do not.
    """
    table = {name for name, *_ in checks()}
    derailing = [f"ward.{rule}" for rule in derailment_rules()]
    tabled = sorted(rule for rule in derailing if rule in table)
    if set(tabled) != table:
        raise RuntimeError(
            f"the corpus derails on {len(set(tabled))} of the {len(table)} table rows; the "
            f"replay summary claims one session per row. Missing: {sorted(table - set(tabled))}")
    if len(tabled) != len(table):
        raise RuntimeError(
            f"{len(tabled)} derailing sessions cover {len(table)} rows; a row is named twice")
    return len(tabled), sorted(set(derailing) - table)


def derailment_rules() -> list[str]:
    """The rule each derailing session declares, in corpus order.

    The README's enumeration used to be a hand-written list of five beside a count that was
    computed. Six sessions were added and the sentence read "11 derailments" and then named five
    of them, which is a claim disagreeing with itself inside one generated block. A list derived
    from the corpus cannot drift from the count derived from the same corpus.
    """
    rules = []
    for path in sorted((ROOT / "eval" / "corpus").glob("*.jsonl")):
        header = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        if header.get("expect", "fires") != "none" and header.get("rule"):
            rules.append(header["rule"].removeprefix("ward."))
    return rules


def run(command: list[str], *, cwd: pathlib.Path = ROOT, input_text: str | None = None) -> int:
    return subprocess.run(command, cwd=cwd, input=input_text, text=True, env=child_env(),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def replay_exit() -> int:
    return run([sys.executable, "eval/replay.py"])


def dispatch_exit() -> int:
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/etc/ward-smoke", "content": "x"},
        "cwd": "/tmp",
    }
    return run([str(ROOT / "plugin" / "hooks" / "dispatch.sh")],
               input_text=json.dumps(event))


MEASUREMENTS = {
    "check-count": check_count,
    "contiguous-count": contiguous_count,
    "suite-count": suite_count,
    "replay-exit": replay_exit,
    "dispatch-exit": dispatch_exit,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("measurement", choices=sorted(MEASUREMENTS))
    args = parser.parse_args()
    print(MEASUREMENTS[args.measurement]())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

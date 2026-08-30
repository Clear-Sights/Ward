#!/usr/bin/env python3
"""Print repository-owned measurements used by README evidence."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent


def checks() -> list[tuple[str, str, str]]:
    sys.path.insert(0, str(ROOT / "plugin"))
    from ward.checks import CHECKS
    return CHECKS


def check_count() -> int:
    return len(checks())


def contiguous_count() -> int:
    names = [row[0] for row in checks()]
    first = names.index("ward.timing_unsafe_compare")
    last = names.index("ward.paramiko_host_key_weakened")
    return last - first + 1


def suite_count() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=ROOT, text=True, capture_output=True,
    )
    output = proc.stdout + proc.stderr
    match = re.search(r"^Ran (\d+) tests? in ", output, re.MULTILINE)
    if proc.returncode or not match:
        raise RuntimeError("unit suite did not produce a passing test count")
    return int(match.group(1))


def corpus_counts() -> tuple[int, int]:
    paths = sorted((ROOT / "eval" / "corpus").glob("*.jsonl"))
    headers = [json.loads(path.read_text(encoding="utf-8").splitlines()[0]) for path in paths]
    derailments = sum(header.get("expect", "fires") != "none" for header in headers)
    return len(paths), derailments


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
    return subprocess.run(command, cwd=cwd, input=input_text, text=True,
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

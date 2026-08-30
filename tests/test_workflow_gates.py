"""A workflow that runs the suite must read how many tests it collected.

`python -m unittest discover` prints OK and exits 0 when it collects NOTHING. A workflow step
that runs it bare therefore reports green forever on a suite that stopped being found -- rename
`tests/`, break an import at module scope, and the step is still green. The suite's absence
becomes its own pass.

`ci.yml` already knew this: its unit-suite step carries the guard and a comment explaining the
defect by name. `release.yml` -- the workflow that decides what SHIPS, and so the more
consequential of the two -- ran `python3 -m unittest discover -s tests` bare. The knowledge was
in the repository and had not reached the workflow that needed it most. This test is what makes
that a thing that cannot happen quietly again: it does not compare the two files, which would
pin their wording; it requires the PROPERTY of every workflow that runs the suite at all.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"

# Reading the collected count means extracting unittest's own "Ran N test(s)" line and deciding
# on it. Any spelling that captures that number and compares it satisfies this; the two markers
# below are what such a step must contain to be doing it at all.
_RUNS_SUITE = re.compile(r"unittest\s+discover")
# Extracting the count is not enough: the value has to DECIDE something. A workflow that pulls
# "Ran N" into a variable and never tests it is exactly as blind as one that never pulled it, and
# the earlier version of this law accepted the sed alone -- so a dead assignment, or that literal
# sitting in a comment, kept it green. Both halves are required now.
_EXTRACTS_COUNT = "s/^Ran "        # the sed that reads unittest's own "Ran N tests" line
_DECIDES_ON_COUNT = re.compile(
    r"""\[\s*["']?\$\{?ran\}?["']?\s*(?:-eq|-lt|-le|=)\s*["']?0["']?\s*\]"""
    r"""|\[\s*-z\s*["']?\$\{?ran\}?["']?\s*\]""")


class EveryWorkflowThatRunsTheSuiteReadsItsCount(unittest.TestCase):
    def test_the_check_has_a_subject(self) -> None:
        files = sorted(WORKFLOWS.glob("*.yml"))
        self.assertTrue(files, f"no workflows under {WORKFLOWS}; nothing below is checked")
        running = [f.name for f in files if _RUNS_SUITE.search(f.read_text())]
        self.assertTrue(running, "no workflow runs the unit suite at all, so this law is vacuous")

    def test_every_such_workflow_reads_the_collected_count(self) -> None:
        offenders = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text()
            if not _RUNS_SUITE.search(text):
                continue
            if _EXTRACTS_COUNT not in text:
                offenders.append(f"{path.name} (never extracts the 'Ran N' count)")
                continue
            if not _DECIDES_ON_COUNT.search(text):
                offenders.append(
                    f"{path.name} (extracts the count and never tests it: a value nothing "
                    f"branches on is a value nothing checks)")
                continue
            # The count can only be read if `discover` was asked to print it. Checked on the
            # INVOKING lines -- those that actually run an interpreter -- because both files
            # also name `unittest discover` inside the comment explaining this very defect, and
            # matching that prose instead of the command is how a check ends up grading itself.
            invocations = [line for line in text.splitlines()
                           if _RUNS_SUITE.search(line) and re.search(r"\bpython3?\b", line)]
            if not invocations:
                offenders.append(f"{path.name} (names `unittest discover` only in prose)")
            elif any(" -v" not in line for line in invocations):
                offenders.append(f"{path.name} (discover without -v: no 'Ran N' line to read)")
        self.assertEqual(
            [], offenders,
            f"these workflows run `unittest discover` without reading how many tests it "
            f"collected: {offenders}. `discover` exits 0 on zero collected tests, so such a "
            f"step is green on a suite that no longer exists.")


if __name__ == "__main__":
    unittest.main()

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



def _run_steps(path: Path) -> list:
    """[(label, shell script)] for each workflow step that has a `run:` block.

    A hand-rolled splitter, and NOT because parsing YAML is hard. Ward declares zero package
    dependencies -- pyproject's `dependencies = []`, and README says so in a sentence a reader
    relies on -- so importing PyYAML here would make the suite unrunnable on a clean checkout and
    would make that sentence false. A first version of this test did import it; this is the
    correction.

    STATED LIMIT: this understands the shape GitHub Actions workflows in THIS repository are
    written in -- `- name:` starting a step, `run: |` opening a block scalar, the block ending at
    the next line indented no further than the `run:` key. A workflow written in flow style, or
    with a folded scalar, is not split correctly, and the law that reads these steps would then
    see a step it cannot check. `test_the_step_scan_finds_the_steps` is the guard against that:
    it fails if the splitter stops finding the suite anywhere.
    """
    steps, label, script, run_indent = [], None, None, None
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if script is not None:
            if stripped and indent <= run_indent:
                steps.append((f"{path.name}:{label or 'unnamed step'}", "\n".join(script)))
                script = None
            else:
                script.append(raw)
                continue
        if stripped.startswith("- name:"):
            label = stripped[len("- name:"):].strip()
        elif stripped.startswith("- ") and ":" in stripped and "name:" not in stripped:
            label = None
        if re.match(r"run:\s*[|>]", stripped):
            run_indent, script = indent, []
        elif stripped.startswith("run:"):
            steps.append((f"{path.name}:{label or 'unnamed step'}", stripped[len("run:"):].strip()))
    if script is not None:
        steps.append((f"{path.name}:{label or 'unnamed step'}", "\n".join(script)))
    return steps


class EveryWorkflowThatRunsTheSuiteReadsItsCount(unittest.TestCase):
    def test_the_check_has_a_subject(self) -> None:
        files = sorted(WORKFLOWS.glob("*.yml"))
        self.assertTrue(files, f"no workflows under {WORKFLOWS}; nothing below is checked")
        running = [f.name for f in files if _RUNS_SUITE.search(f.read_text())]
        self.assertTrue(running, "no workflow runs the unit suite at all, so this law is vacuous")

    def test_every_such_workflow_reads_the_collected_count(self) -> None:
        """Per STEP, not per file. A workflow is a list of steps and each runs its own shell.

        The previous form searched a workflow's WHOLE text for the extraction fragment and for a
        comparison on `ran`. Those can sit in a different step, or in a comment, while the step
        that actually runs `unittest discover` runs it bare -- and the law about that step stayed
        green. The unit is the step, so the step is the unit here: the YAML is parsed, the step
        whose `run:` invokes `unittest discover` is found, and THAT script must extract the count
        and branch on it.
        """
        offenders = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            for name, script in _run_steps(path):
                if True:
                    invocations = [line for line in script.splitlines()
                                   if _RUNS_SUITE.search(line) and re.search(r"\bpython3?\b", line)]
                    if not invocations:
                        continue
                    if any(" -v" not in line for line in invocations):
                        offenders.append(f"{name} (discover without -v: no 'Ran N' line to read)")
                        continue
                    if _EXTRACTS_COUNT not in script:
                        offenders.append(f"{name} (never extracts the 'Ran N' count in the step "
                                         f"that runs the suite)")
                    elif not _DECIDES_ON_COUNT.search(script):
                        offenders.append(f"{name} (extracts the count and never tests it in the "
                                         f"step that runs the suite)")
        self.assertEqual(
            [], offenders,
            f"these workflow STEPS run `unittest discover` without reading how many tests it "
            f"collected: {offenders}. `discover` exits 0 on zero collected tests, so such a step "
            f"is green on a suite that no longer exists.")

    def test_the_step_scan_finds_the_steps(self) -> None:
        """A parse that finds no invoking step would make the law above pass over everything."""
        found = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            for name, script in _run_steps(path):
                if _RUNS_SUITE.search(script):
                    found.append(name)
        self.assertTrue(
            found,
            "no workflow STEP was found running the unit suite, so the law above compared "
            "nothing. Either the parse broke or the suite stopped being run in CI.")


if __name__ == "__main__":
    unittest.main()

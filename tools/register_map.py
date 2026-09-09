#!/usr/bin/env python3
"""Grade ward's coverage of the blindspot register.

docs/REGISTER.md is a vendored copy; the source is measure-zero-dev/REGISTER.md.
docs/REGISTER-MAP.tsv gives every entry in it one of two verdicts:

  RUNNER          a named row of the ordered denial table, or a structural
                  property of the dispatcher, denies the act the entry names
  OUT-OF-SUBJECT  the entry is about a statement, a sequence of acts, or code
                  ward does not execute. Ward denies one pending act on its
                  typed fields; a defect that only exists across acts belongs
                  to keel, and one that only exists in a claim belongs to
                  makoto. The note says which.

There is deliberately no NOT-COUNTABLE verdict here. Ward parses no free text
and judges no intent, so an entry it cannot decide from the call's typed fields
is not a gap in ward -- it is another tool's subject, and the note names it.

The row population is closed at 11 and this runner does not widen it. A verdict
with no note is NOT-EVALUABLE and exits 2.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "plugin"))
REGISTER = ROOT / "docs" / "REGISTER.md"
MAP = ROOT / "docs" / "REGISTER-MAP.tsv"
VERDICTS = {"RUNNER", "OUT-OF-SUBJECT"}
ENTRY_RX = re.compile(r"^([A-G]\d+)\s+[A-Z]")
ROWS = 11

from ward.checks import CHECKS  # noqa: E402


def main():
    entries = [m.group(1) for m in
               (ENTRY_RX.match(ln) for ln in REGISTER.read_text(encoding="utf-8").splitlines())
               if m]
    table = {row[0] for row in CHECKS}

    rows, errors = {}, []
    if len(table) != ROWS:
        errors.append(f"denial table carries {len(table)}, not the stated {ROWS}")

    for n, line in enumerate(MAP.read_text(encoding="utf-8").splitlines()[1:], start=2):
        if not line.strip():
            continue
        entry, verdict, runner, note = line.split("\t")
        if entry in rows:
            errors.append(f"line {n}: {entry} stated twice")
        rows[entry] = (verdict, runner, note)
        if verdict not in VERDICTS:
            errors.append(f"line {n}: {entry} verdict {verdict!r} is not one of {sorted(VERDICTS)}")
        if not note.strip():
            errors.append(f"line {n}: {entry} has a verdict and no note")
        if verdict == "RUNNER":
            if runner.startswith("ward.") and runner not in table:
                errors.append(f"line {n}: {entry} cites {runner}, which the table does not carry")
            elif "/" in runner and not (ROOT / runner).exists():
                errors.append(f"line {n}: {entry} cites {runner}, which is not on disk")
        elif runner != "-":
            errors.append(f"line {n}: {entry} is {verdict} but names a runner")

    for missing in sorted(set(entries) - set(rows)):
        errors.append(f"register entry {missing} has no row in the map")
    for invented in sorted(set(rows) - set(entries)):
        errors.append(f"map row {invented} is not an entry in the register")

    counts = {v: sum(1 for r in rows.values() if r[0] == v) for v in sorted(VERDICTS)}
    cited = {r[1] for r in rows.values() if r[0] == "RUNNER" and r[1].startswith("ward.")}
    print(f"REGISTER MAP  register entries={len(entries)}  rows={len(rows)}  table={len(table)}")
    for v, c in counts.items():
        print(f"  {v:<15s} {c}")
    print(f"  table rows cited {len(cited)} of {len(table)}")
    for idle in sorted(table - cited):
        print(f"    no register entry names {idle}")
    if errors:
        print(f"  NOT-EVALUABLE   {len(errors)}")
        for e in errors:
            print(f"    {e}")
        return 2
    print("REGISTER MAP: every entry carried, every row cited is in the table, every verdict explained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
